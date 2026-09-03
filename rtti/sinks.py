"""Where recovered metadata gets written.

The same decoding produces the same facts whether they are pushed straight
into a BinaryView or contributed to a DebugInfo container, but the two
destinations accept different things and at different times.  Everything that
mutates state goes through a sink so the recovery logic stays destination
agnostic.

A DebugInfo parser runs during the Discovery phase, before linear sweep has
finished, so data variables laid down there stop the sweep from inventing
functions over the RTTI tables in the first place rather than deleting them
afterwards.  It cannot express comments and it cannot remove anything, so
those stay on the view path.
"""

import binaryninja as bn
from binaryninja import (FunctionParameter, NamedTypeReferenceClass, Symbol,
                         SymbolType, Type, Variable, VariableSourceType)

TAG = "delphinja"


class Sink(object):
    supports_comments = True

    def add_type(self, name, ty):
        raise NotImplementedError

    def add_data_var(self, addr, ty, name):
        raise NotImplementedError

    def add_function(self, addr, name, self_type=None, register_cc=True):
        """Return True when the function was named.

        `register_cc` says the class metadata fixes the convention.  It does
        for a method the class publishes; it does not for an interface vtable
        thunk, whose convention the interface declares.
        """
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
        self.cc = _register_convention(bv)

    def add_type(self, name, ty):
        self.bv.define_user_type(name, ty)

    def add_data_var(self, addr, ty, name):
        self.bv.define_user_data_var(addr, ty, name)

    def set_comment(self, addr, text):
        self.bv.set_comment_at(addr, text)

    def add_function(self, addr, name, self_type=None, register_cc=True):
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
            self.pending_self.append((addr, self_type, register_cc))
        return True

    def finish(self):
        """Assert the convention and type Self once analysis has run.

        Parameter variables do not exist until the function has been analysed,
        and functions created moments ago have not been, so this cannot run
        inline with the naming.
        """
        if not self.pending_self:
            return 0
        self.bv.update_analysis_and_wait()
        typed = 0
        for addr, self_type, register_cc in self.pending_self:
            func = self.bv.get_function_at(addr)
            if func is None:
                continue
            try:
                typed += apply_method(func, self_type,
                                      self.cc if register_cc else None)
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
        self.cc = _register_convention(bv)

    def add_type(self, name, ty):
        self.bv.define_type(Type.generate_auto_type_id("delphinja", name),
                            name, ty)

    def add_data_var(self, addr, ty, name):
        self.bv.define_data_var(addr, ty, name)

    def set_comment(self, addr, text):
        self.bv.set_comment_at(addr, text)

    def add_function(self, addr, name, self_type=None, register_cc=True):
        bv = self.bv
        func = bv.get_function_at(addr)
        if func is None:
            # The metadata is proof this is an entry point even though nothing
            # has reached it yet. Deliberately NOT auto_discovered: these
            # functions are reached only through Delphi's interface and dynamic
            # method tables, so nothing points at them until the applier has
            # declared those tables as arrays of code pointers, and
            # core.module.deleteUnusedAutoFunctions deletes unreferenced
            # auto-discovered functions. The typed tables do carry those
            # references, but the ordering between the two is not guaranteed.
            # Still an auto function: re-derivable, and not recorded as
            # something the user asserted.
            func = bv.add_function(addr)
            if func is None:
                return False
            self.created += 1
        elif not (func.symbol is None or func.symbol.auto):
            return False                            # respect existing names
        bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
        if self_type is not None:
            self.pending_self.append((addr, self_type, register_cc))
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

    def add_function(self, addr, name, self_type=None, register_cc=True):
        ftype = None
        if self_type is not None and register_cc:
            # Self in the prototype replaces the view path's deferred pass:
            # the parameter is named and typed the moment the function exists.
            # A prototype is the only way this container can express either
            # the convention or Self, so it is built only where the metadata
            # fixes the convention; an interface thunk is left to analysis.
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


def apply_method(func, self_type, cc):
    """Assert on `func` what the class metadata proves about it.

    Returns 1 when Self was typed, so callers can count it.

    The convention is set on the function rather than through a replacement
    prototype.  `register` and `regparm` claim the same three registers but
    disagree on who pops the stack and on the order the remaining arguments
    are pushed, so a method with more than three parameters has its stack
    arguments transposed under the wrong one; asserting a whole prototype to
    fix that would throw away the return type and parameter list analysis has
    already worked out.
    """
    if cc is not None:
        current = func.calling_convention
        if current is None or current.name != cc.name:
            func.calling_convention = cc
    var = self_variable(func, cc)
    if var is None:
        return 0
    func.create_user_var(var, self_type, "Self")
    return 1


def self_variable(func, cc):
    """The variable Self arrives in.

    Delphi puts Self in the convention's first integer argument register, so
    the variable is named by its location rather than by asking which one
    analysis calls parameter zero.  The parameter list is still the one
    derived under the convention analysis guessed, and where that guess was a
    stack convention its parameter zero is a different variable entirely.

    Which register that is comes from the convention -- `int_arg_regs[0]`,
    which is EAX once x86 resolves it -- and is not written down here.

    With no convention to go on -- an interface thunk, whose convention the
    interface declares -- analysis's own parameter zero is the best answer.
    """
    regs = cc.int_arg_regs if cc is not None else None
    if regs:
        return Variable(func, VariableSourceType.RegisterVariableSourceType, 0,
                        func.arch.get_reg_index(regs[0]))
    params = func.parameter_vars
    return params[0] if len(params) else None


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
