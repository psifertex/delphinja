"""Where recovered metadata gets written.

The same decoding produces the same facts whether they are pushed straight
into a BinaryView or contributed to a DebugInfo container, but the two
destinations accept different things and at different times.  Everything that
mutates state goes through a sink so the recovery logic stays destination
agnostic.

A DebugInfo parser runs during the Discovery phase, before linear sweep has
finished, which is why it is the better destination: data variables laid down
there stop the sweep from inventing functions over the RTTI tables in the
first place, instead of deleting them afterwards.  It cannot express comments
and it cannot remove anything, so those stay on the view path.
"""

import binaryninja as bn
from binaryninja import (FunctionParameter, NamedTypeReferenceClass, Symbol,
                         SymbolType, Type)

TAG = "delphi"


class Sink(object):
    supports_comments = True

    def add_type(self, name, ty):
        raise NotImplementedError

    def add_data_var(self, addr, ty, name):
        raise NotImplementedError

    def add_function(self, addr, name, self_type=None):
        """Return True when the function was named."""
        raise NotImplementedError

    def set_comment(self, addr, text):
        pass

    def finish(self):
        """Deferred work that cannot run inline."""


class ViewSink(Sink):
    """Direct BinaryView mutation, for the interactive plugin commands."""

    supports_comments = True

    def __init__(self, bv, md):
        self.bv = bv
        self.md = md
        self.created = 0
        self.pending_self = []

    def add_type(self, name, ty):
        self.bv.define_user_type(name, ty)

    def add_data_var(self, addr, ty, name):
        self.bv.define_user_data_var(addr, ty, name)

    def set_comment(self, addr, text):
        self.bv.set_comment_at(addr, text)

    def add_function(self, addr, name, self_type=None):
        bv = self.bv
        func = bv.get_function_at(addr)
        if func is None:
            # A published or dynamic method that analysis never reached is
            # still a real entry point; the table proves it.
            func = bv.create_user_function(addr)
            if func is None:
                return False
            self.created += 1
        elif not (func.symbol is None or func.symbol.auto):
            return False                            # respect existing names
        bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
        if self_type is not None:
            self.pending_self.append((addr, self_type))
        return True

    def finish(self):
        """Type Self once analysis has produced parameter variables.

        Parameter variables do not exist until the function has been analysed,
        and functions created moments ago have not been, so this cannot run
        inline with the naming.
        """
        if not self.pending_self:
            return 0
        self.bv.update_analysis_and_wait()
        typed = 0
        for addr, self_type in self.pending_self:
            func = self.bv.get_function_at(addr)
            if func is None or not len(func.parameter_vars):
                continue
            try:
                func.create_user_var(func.parameter_vars[0], self_type, "Self")
                typed += 1
            except Exception as exc:
                bn.log_warn("Self on 0x%x: %s" % (addr, exc), TAG)
        self.pending_self = []
        return typed


class AutoSink(Sink):
    """Analysis-level mutation, for the workflow path.

    A workflow contributes analysis results, not user edits, so everything it
    writes should be auto-level: the user's own changes then win on conflict,
    the results do not masquerade as hand edits, and -- the reason this matters
    in practice -- auto mutations do not each generate an undo record and the
    notification traffic that goes with it. On a Delphi 7 sample the plugin
    makes roughly 2400 mutations, so the difference is not marginal.
    """

    supports_comments = True

    def __init__(self, bv, md):
        self.bv = bv
        self.md = md
        self.created = 0
        self.pending_self = []

    def add_type(self, name, ty):
        self.bv.define_type(Type.generate_auto_type_id("delphi_rtti", name),
                            name, ty)

    def add_data_var(self, addr, ty, name):
        self.bv.define_data_var(addr, ty, name)

    def set_comment(self, addr, text):
        self.bv.set_comment_at(addr, text)

    def add_function(self, addr, name, self_type=None):
        bv = self.bv
        func = bv.get_function_at(addr)
        if func is None:
            # The metadata is proof this is an entry point even though nothing
            # has reached it yet. Deliberately NOT auto_discovered: these
            # functions are reached only through Delphi's interface and dynamic
            # method tables, which nothing models as arrays of code pointers, so
            # they carry no references at all -- and core.module.
            # deleteUnusedAutoFunctions then removed every one of them, taking
            # their names and WARP matches with them. Losing an adjustor thunk
            # that way also stranded its jump target, which a misaligned sweep
            # artifact then absorbed. Still an auto function: re-derivable, and
            # not recorded as something the user asserted.
            func = bv.add_function(addr)
            if func is None:
                return False
            self.created += 1
        elif not (func.symbol is None or func.symbol.auto):
            return False                            # respect existing names
        bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
        if self_type is not None:
            self.pending_self.append((addr, self_type))
        return True

    def finish(self):
        return 0


class DebugInfoSink(Sink):
    """Contributes to a DebugInfo container from inside a parser callback.

    Never call update_analysis_and_wait() from here -- this runs on the
    analysis thread, mid-analysis.
    """

    supports_comments = False

    def __init__(self, debug_info, bv, md):
        self.debug_info = debug_info
        self.bv = bv
        self.md = md
        self.cc = _register_convention(bv)
        self.self_typed = 0

    def _components(self, extra):
        return ["Delphi"] + [c for c in extra if c]

    def add_type(self, name, ty):
        self.debug_info.add_type(name, ty, self._components(["Types"]))

    def add_data_var(self, addr, ty, name):
        # No components here, deliberately.  Binary Ninja's
        # _component_data_variable_added callback passes the BNDataVariable
        # pointer to DataVariable.from_core_struct without dereferencing it
        # (binaryview.py:1481 -- compare _data_var_added at :1171, which
        # correctly uses var[0]), so every data variable added to a component
        # raises AttributeError in the notification path.  Functions are
        # unaffected: _component_function_added takes the handle directly.
        self.debug_info.add_data_variable(addr, ty, name)

    def add_function(self, addr, name, self_type=None):
        ftype = None
        if self_type is not None:
            # Self in the prototype replaces the view path's deferred pass:
            # the parameter is named and typed the moment the function exists.
            ftype = Type.function(Type.void(),
                                  [FunctionParameter(self_type, "Self")],
                                  calling_convention=self.cc)
            self.self_typed += 1
        owner = name.split(".")[0] if "." in name else "Global"
        return bool(self.debug_info.add_function(bn.debuginfo.DebugFunctionInfo(
            address=addr,
            # short_name only: an undemanglable raw_name becomes func.name.
            short_name=name,
            function_type=ftype,
            platform=self.bv.platform,
            components=self._components([owner]))))


def _register_convention(bv):
    """Delphi's `register` convention: Self in EAX, then EDX, ECX.

    Binary Ninja registers `register` on the x86 architecture rather than on
    any platform, so bv.platform.calling_conventions never contains it. The
    plugin requires core 9696 or later, where it always exists -- regparm is
    not a substitute, since it pushes stack arguments right to left where
    Delphi pushes left to right.
    """
    try:
        return bv.arch.calling_conventions.get("register")
    except Exception:
        return None


def self_pointer(bv, factory, vmt):
    """Pointer to the class struct for `vmt`, as a named type reference."""
    return Type.pointer(bv.arch, Type.named_type_reference(
        NamedTypeReferenceClass.StructNamedTypeClass,
        factory.qname(vmt.name)))
