"""Delphi type strings -> Binary Ninja types.

Knowledge base procedures carry a full prototype: a return type, and per
argument a name, a type and whether it is passed by reference.  `Self` is
already present as the first argument of a method, and constructors and
destructors carry Delphi's hidden alloc/free flag as `_Dv_`, so the argument
list can be used as-is rather than reconstructed.

Type strings are `Unit.Name`, with a long tail -- 1563 distinct return types
and 5314 distinct argument types across Delphi 7.  The table below covers the
types that actually recur; everything else falls back on the shape of the name,
which for Delphi is unusually reliable: a leading `P` means pointer, a leading
`T` means a class reference (itself a pointer), and `low..high` is a subrange.
"""

from binaryninja import Type
from binaryninja.enums import TypeClass

# Delphi's conventions, under the names Binary Ninja gives them. `register`
# and `pascal` are registered on the x86 *architecture*, never on a platform,
# so they have to be looked up through bv.arch -- which is why an earlier
# platform-only lookup silently found neither. Both need a core >= 5.4.9696.
CALL_KINDS = {0: "register", 1: "cdecl", 2: "pascal", 3: "stdcall",
              4: "stdcall"}          # safecall is stdcall plus an HRESULT

# No fallbacks. On a core that lacks these, emitting the nearest available
# convention would bake a wrong argument order into a published library --
# regparm pushes right to left where Delphi's register pushes left to right,
# and every older stack convention has the same problem versus pascal. A
# signature with no convention is recoverable by analysis; a signature with
# the wrong one is not.

_BY_VALUE = 0x21
_BY_REF = 0x22
_SAFECALL = 4


def _base(bv):
    a = bv.arch
    ptr = lambda t: Type.pointer(a, t)
    return {
        "integer": Type.int(4), "longint": Type.int(4), "smallint": Type.int(2),
        "shortint": Type.int(1), "byte": Type.int(1, False),
        "word": Type.int(2, False), "cardinal": Type.int(4, False),
        "longword": Type.int(4, False), "dword": Type.int(4, False),
        "ulong": Type.int(4, False), "uint": Type.int(4, False),
        "int64": Type.int(8), "uint64": Type.int(8, False),
        "boolean": Type.bool(), "bytebool": Type.bool(),
        "wordbool": Type.int(2), "longbool": Type.int(4), "bool": Type.int(4),
        "char": Type.char(), "ansichar": Type.char(),
        "widechar": Type.wide_char(2),
        "single": Type.float(4), "double": Type.float(8),
        "extended": Type.float(10), "real": Type.float(8),
        "real48": Type.float(6), "comp": Type.int(8),
        "currency": Type.int(8), "tdatetime": Type.float(8),
        "hresult": Type.int(4), "pointer": ptr(Type.void()),
        "ansistring": ptr(Type.char()), "string": ptr(Type.char()),
        "shortstring": ptr(Type.char()),
        "widestring": ptr(Type.wide_char(2)),
        "unicodestring": ptr(Type.wide_char(2)),
        "pchar": ptr(Type.char()), "pansichar": ptr(Type.char()),
        "pwidechar": ptr(Type.wide_char(2)),
        "variant": Type.array(Type.int(1, False), 16),
        "olevariant": Type.array(Type.int(1, False), 16),
        "void": Type.void(),
        "": Type.void(),
    }


class TypeMap(object):
    def __init__(self, bv, extra=None):
        """`extra` adds dialect-specific names to the base table.

        Free Pascal shares most of Delphi's type vocabulary but not all of it
        (`QWord`, `PtrInt`, `RawByteString`, ...), and it spells types in
        upper case; `resolve` already lowercases, so a dialect only has to
        contribute the names Delphi does not have.  Nothing is overridden by
        default, so the Delphi libraries are unaffected.
        """
        self.bv = bv
        self.base = _base(bv)
        if extra:
            self.base.update(extra)
        self.void_ptr = Type.pointer(bv.arch, Type.void())

    def resolve(self, text, classes=None):
        """Best Binary Ninja type for a Delphi type string.

        `classes` is a ClassIndex; when supplied, a class reference resolves to
        a pointer to that class's real struct rather than to void*, which is
        what turns Self_1->__offset(0x8).d into Self_1->FCount in a matched
        function.
        """
        if not text:
            return Type.void()
        name = text.rsplit(".", 1)[-1].strip()
        hit = self.base.get(name.lower())
        if hit is not None:
            return hit
        if classes is not None:
            ref = classes.reference(self.bv, name)
            if ref is not None:
                return ref
        if ".." in text:                       # subrange, e.g. false..true
            lo = text.split("..", 1)[0].strip().lower()
            return Type.bool() if lo in ("false", "0") else Type.int(4)
        if len(name) > 1 and name[0] in "Pp" and name[1].isupper():
            return self.void_ptr                # PFoo: pointer by convention
        if len(name) > 1 and name[0] in "TtIiEe" and name[1].isupper():
            return self.void_ptr                # class/interface reference
        return Type.int(4)                      # Delphi's default word size

    def prototype(self, proc, classes=None):
        """(return_type, [FunctionParameter]) for a knowledge base procedure."""
        from binaryninja import FunctionParameter
        params = []
        for a in proc["args"]:
            t = self.resolve(a["type"], classes)
            if a["tag"] == _BY_REF:
                t = Type.pointer(self.bv.arch, t)
            params.append(FunctionParameter(t, a["name"] or None))
        ret = (self.resolve(proc["typedef"], classes) if proc["typedef"]
               else Type.void())

        if proc["call_kind"] == _SAFECALL:
            # safecall is stdcall at the ABI level, but the compiler rewrites
            # the signature: the declared result becomes a hidden trailing out
            # parameter and the function actually returns an HRESULT, which the
            # caller checks and turns back into an exception. Modelling that in
            # the prototype is the only way to get it right -- Binary Ninja has
            # no safecall convention, and registering a custom one would emit a
            # convention name that no consumer of the signature library could
            # resolve.
            if not ret.type_class == TypeClass.VoidTypeClass:
                params.append(FunctionParameter(
                    Type.pointer(self.bv.arch, ret), "Result"))
            ret = Type.int(4)          # HRESULT

        return ret, params

    def convention(self, proc):
        want = CALL_KINDS.get(proc["call_kind"])
        if not want:
            return None
        return self.bv.arch.calling_conventions.get(want)

    def function_type(self, proc, classes=None):
        ret, params = self.prototype(proc, classes)
        return Type.function(ret, params, calling_convention=self.convention(proc))
