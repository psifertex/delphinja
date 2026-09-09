"""Free Pascal prototypes for staged functions.

`types.py` already knows Object Pascal's type vocabulary, and Free Pascal
shares most of it, so this only adds the names Delphi does not have and turns
a demangled symbol into a Binary Ninja function type.

Two things differ from the Delphi side.  Type names come out of the mangled
symbol *uppercased and unqualified* -- `mangledparaname` is the declared type
name, nothing more -- so there is no unit to disambiguate `TFoo` with, and
class references stay `void*` rather than becoming real structs (the Delphi
class layouts come from IDR type records, which have no FPC equivalent short
of parsing a `.ppu`).  And hidden parameters are missing by construction, so
`fpcname.hidden_params` puts them back.

The calling convention is `register`: `globtype.pas` sets
`pocall_default = pocall_register` on both i386 and x86_64, and on i386 that is
the same Borland-compatible convention the Delphi libraries already emit.
"""

from binaryninja import FunctionParameter, Type

from . import fpcname
from .delphitypes import TypeMap

# `pocall_default = pocall_register` on both x86 architectures, but that name
# means different things on each. On i386 it is the Borland-compatible
# register convention Binary Ninja calls "register" -- registered on the x86
# *architecture*, never on a platform, which is why a platform-only lookup
# finds nothing. On x86_64 the compiler routes every convention through
# `x86_64_use_ms_abi` on win64 targets, so it is simply the Microsoft x64 ABI.
CONVENTIONS = {"x86": "register", "x86_64": "win64"}


def _extra(bv):
    a = bv.arch
    ptr = lambda t: Type.pointer(a, t)
    width = bv.arch.address_size
    return {
        "qword": Type.int(8, False), "qwordbool": Type.int(8),
        "ptrint": Type.int(width), "ptruint": Type.int(width, False),
        "sizeint": Type.int(width), "sizeuint": Type.int(width, False),
        "valsint": Type.int(width), "valuint": Type.int(width, False),
        "nativeint": Type.int(width), "nativeuint": Type.int(width, False),
        "codepointer": ptr(Type.void()), "typedfile": ptr(Type.void()),
        "rawbytestring": ptr(Type.char()), "utf8string": ptr(Type.char()),
        "utf8char": Type.char(), "unicodechar": Type.wide_char(2),
        "ucs4char": Type.int(4, False), "ucs4string": ptr(Type.int(4, False)),
        "openstring": ptr(Type.char()),
        "pbyte": ptr(Type.int(1, False)), "pword": ptr(Type.int(2, False)),
        "plongint": ptr(Type.int(4)), "pdword": ptr(Type.int(4, False)),
        "pointer": ptr(Type.void()),
        # An untyped `var`/`const` parameter; the mangler spells it in lower
        # case, which is how it stays distinguishable from a real type.
        "formal": ptr(Type.void()),
        "text": ptr(Type.void()), "file": ptr(Type.void()),
        "tclass": ptr(Type.void()), "tobject": ptr(Type.void()),
        # x86_64-win64 has no 80-bit float; `Extended` is an alias for Double
        # there, and Delphi's 10-byte entry would be wrong.
        "extended": Type.float(10 if width == 4 else 8),
    }


class FpcTypeMap(TypeMap):
    def __init__(self, bv):
        TypeMap.__init__(self, bv, extra=_extra(bv))

    def resolve(self, text, classes=None):
        if text:
            low = text.lower()
            if low.startswith("array_of_"):
                if low == "array_of_const":
                    return self.void_ptr
                inner = TypeMap.resolve(self, text[len("array_of_"):], classes)
                return Type.pointer(self.bv.arch, inner)
            if low.startswith("file$of$"):
                return self.void_ptr
        return TypeMap.resolve(self, text, classes)

    # -- prototypes ------------------------------------------------------

    def prototype(self, name):
        """(return type, parameters) for a demangled `fpcname.Name`.

        `None` when the symbol carries no usable prototype: a hashed parameter
        list is unrecoverable from the symbol alone, and claiming an empty one
        would be worse than claiming nothing.
        """
        if name.hashed:
            return None
        before, after = fpcname.hidden_params(
            name, result_last=self.bv.arch.address_size == 4)
        params = [FunctionParameter(self.void_ptr, _label(h)) for h in before]
        for i, raw in enumerate(name.params):
            t = self.resolve(raw)
            params.append(FunctionParameter(t, "arg%d" % (i + 1)))
            # An open array is passed as (pointer, high index) unless the
            # convention is cdecl-like -- paramanager.push_high_param.
            if raw.lower().startswith("array_of_") and raw.lower() != "array_of_const":
                params.append(FunctionParameter(Type.int(4), "high%d" % (i + 1)))
        ret = self.resolve(name.ret) if name.ret else Type.void()
        for hidden in after:
            # The hidden $result is a var parameter: a pointer to the result.
            params.append(FunctionParameter(
                Type.pointer(self.bv.arch, ret), _label(hidden)))
        return ret, params

    def convention(self, name=None):
        want = CONVENTIONS.get(self.bv.arch.name)
        return self.bv.arch.calling_conventions.get(want) if want else None

    def function_type(self, name):
        proto = self.prototype(name)
        if proto is None:
            return None
        ret, params = proto
        convention = self.convention()
        if convention is None:
            # No fallback, for the same reason as the Delphi side: a signature
            # with no convention is recoverable by analysis, one with the
            # wrong convention is not.
            return None
        return Type.function(ret, params, calling_convention=convention)


def _label(hidden):
    return {"self": "Self", "vmt": "vmt", "parentfp": "parentfp",
            "result": "Result"}.get(hidden, hidden)
