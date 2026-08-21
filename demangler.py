"""Borland / C++Builder / Delphi symbol demangler.

Delphi and C++Builder share a single mangling scheme -- they are two front
ends over the same back end -- so the export tables of a Delphi package, the
import thunks of a BPL and any debug symbols in a Delphi binary all carry
C++Builder mangled names:

    @Forms@TApplication@HandleException$qqrp14System@TObject
      -> void __fastcall Forms::TApplication::HandleException(
             System::TObject *)

The grammar below follows Embarcadero's own `unmangle.c` (RAD Studio,
`$(BDS)/source/cpprtl/Source/misc`), which is the only complete description of
the scheme that exists; the reference implementation walks a source pointer
and a destination buffer, this one is a recursive-descent parser that returns
values instead.  Where the two disagree the reference wins, because its output
is what every other Borland tool (tdump, IDA, the linker map) prints.

Nothing in here reads or writes a BinaryView.  `demangle` is pure and total:
truncated names, unknown type codes and unbalanced `%` all degrade to "name
only" or to a declined result, never to an exception escaping into analysis.
"""

import re

import binaryninja as bn
from binaryninja import Type, QualifiedName
from binaryninja.demangle import Demangler, DemangleResult

DEMANGLER_NAME = "Borland"

# Delphi's `register` convention -- Self/first argument in EAX, then EDX and
# ECX, callee cleans the stack -- is what Borland spells `__fastcall`.  Binary
# Ninja's x86 `fastcall` is the Microsoft one (ECX, EDX), so `r` maps to
# `register` and not to the similarly named convention.
_CALLCONV = {
    "c": ("__cdecl", "cdecl"),
    "p": ("__pascal", "pascal"),
    "r": ("__fastcall", "register"),
    "s": ("__stdcall", "stdcall"),
    "f": ("__fortran", None),
    "y": ("__syscall", None),
    "i": ("__interrupt", None),
    "g": ("__saveregs", None),
}
_DEFAULT_CALLCONV = ("", "cdecl")

_PRIMITIVES = {
    "v": "void", "c": "char", "b": "wchar_t", "s": "short", "i": "int",
    "l": "long", "f": "float", "d": "double", "g": "long double",
    "j": "long long", "o": "bool", "e": "...",
}

# Borland's 32-bit model: long is 4 bytes, long double is the x87 80-bit type.
_PRIMITIVE_WIDTH = {
    "char": (1, True), "wchar_t": (2, None), "short": (2, True),
    "int": (4, True), "long": (4, True), "long long": (8, True),
    "char16_t": (2, None), "char32_t": (4, None),
}
_PRIMITIVE_FLOAT = {"float": 4, "double": 8, "long double": 10}

_OPERATORS = {
    "add": "+", "adr": "&", "and": "&", "asg": "=", "land": "&&",
    "lor": "||", "call": "()", "cmp": "~", "fnc": "()", "dec": "--",
    "div": "/", "eql": "==", "geq": ">=", "gtr": ">", "inc": "++",
    "ind": "*", "leq": "<=", "lsh": "<<", "lss": "<", "mod": "%",
    "mul": "*", "neq": "!=", "new": "new", "not": "!", "or": "|",
    "rand": "&=", "rdiv": "/=", "rlsh": "<<=", "rmin": "-=", "rmod": "%=",
    "rmul": "*=", "ror": "|=", "rplu": "+=", "rrsh": ">>=", "rsh": ">>",
    "rxor": "^=", "subs": "[]", "sub": "-", "xor": "^", "arow": "->",
    "nwa": "new[]", "dele": "delete", "dla": "delete[]",
}
# Not operators at all: the compiler encodes a class' static initialiser and
# finaliser through the same `$b` slot.
_CLASS_INIT = {"cctr": "`class constructor`", "cdtr": "`class destructor`"}

_SPECIAL_TABLES = {
    "FL": "frndl", "CH": "chtbl", "DC": "odtbl",
    "TL": "thrwl", "EC": "ectbl",
}

# Delphi's own generics reach C++ through four hand-written templates whose
# arguments are encoded with an older, kind-tagged scheme.
_DELPHI4_TEMPLATES = re.compile(
    r"(Set|DynamicArray|SmallString|DelphiInterface)\$")

_QUALIFIER = "@"
_ARGLIST = "$"
_TMPLCODE = "%"

# A Borland symbol is `@` (or a bare template) followed by identifier
# characters and the scheme's own punctuation.  Nothing else may appear, which
# is what keeps MSVC (`?`), Itanium (`_Z`), Rust, D and Swift names out.
_CANDIDATE = re.compile(r"\A(@[A-Za-z0-9_$@%#.]+|%[A-Za-z0-9_$@%#.]*%)\Z")
# `@name@12` is a Microsoft-style fastcall decoration, not a Borland symbol.
_MSVC_FASTCALL = re.compile(r"\A@[^@$%]*@\d+\Z")
# Delphi classes and interfaces are `TFoo` / `IFoo` / `EFoo`; unit names are
# `Sysutils`, `Vcl.Forms`, ... .  Used only to decide whether a three-part name
# is Unit::Class::Method (an instance method with a hidden Self) or a plain
# nested routine, which the mangling itself does not record.
_CLASSLIKE = re.compile(r"\A[TIE][A-Z0-9_]")
# A qualified name with nothing decorating it: `Discomp::TFlagType`.
_PLAIN_QUALIFIED = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*\Z")


class _MangleError(ValueError):
    """Raised anywhere the input stops matching the grammar."""


class _Cursor(object):
    """Index into the mangled string; every read is bounds-checked."""

    def __init__(self, text):
        self.s = text
        self.i = 0

    @property
    def eof(self):
        return self.i >= len(self.s)

    def peek(self, offset=0):
        j = self.i + offset
        return self.s[j] if 0 <= j < len(self.s) else ""

    def take(self):
        c = self.peek()
        if not c:
            raise _MangleError("name ends mid-token")
        self.i += 1
        return c

    def expect(self, ch):
        c = self.take()
        if c != ch:
            raise _MangleError("expected %r, found %r" % (ch, c))
        return c

    def read_until(self, stops):
        start = self.i
        while self.i < len(self.s) and self.s[self.i] not in stops:
            self.i += 1
        return self.s[start:self.i]

    def rest(self):
        return self.s[self.i:]


# --------------------------------------------------------------------- types

class _Ty(object):
    """A decoded type: its C++ spelling plus how to build the Binary Ninja one.

    `build` is a callable taking the pointer width so that pointer types can
    be constructed without an Architecture; it returns None (or raises, which
    is caught) whenever the type has no faithful Binary Ninja equivalent, and
    that None propagates outward so a function containing it yields no type
    at all rather than a plausible-looking wrong one.
    """

    def __init__(self, text, build=None, is_void=False, is_ellipsis=False,
                 func=None):
        self.text = text
        self._build = build
        self.is_void = is_void
        self.is_ellipsis = is_ellipsis
        self.func = func

    def binja(self, width):
        if self._build is None:
            return None
        try:
            return self._build(width)
        except Exception:
            return None

    def prefixed(self, prefix):
        """Copy with cv-qualifier text in front, the way the tools print it."""
        if not prefix:
            return self
        text = (prefix + self.text).replace("const const ", "const ")
        return _Ty(text, self._build, self.is_void, self.is_ellipsis,
                   self.func)


def _primitive_builder(name, is_signed, is_unsigned):
    """How to build a primitive's Binary Ninja type, or None if it has none."""
    if name == "void":
        return lambda w: Type.void()
    if name == "bool":
        return lambda w: Type.bool()
    if name in _PRIMITIVE_FLOAT:
        return lambda w, n=_PRIMITIVE_FLOAT[name]: Type.float(n)
    if name == "char" and not (is_signed or is_unsigned):
        return lambda w: Type.char()
    if name == "wchar_t":
        return lambda w: Type.wide_char(2)
    width, default_signed = _PRIMITIVE_WIDTH.get(name, (None, None))
    if width is None:
        return None
    signed = default_signed if default_signed is not None else True
    if is_unsigned:
        signed = False
    elif is_signed:
        signed = True
    return lambda w, n=width, s=signed: Type.int(n, s)


def _requalify(type_obj, is_const, is_volatile):
    """Re-emit a type with cv qualifiers.

    Immutable Type objects cannot be qualified in place, so this goes through
    a mutable builder; if that is not possible the unqualified type is still
    a better answer than none.
    """
    try:
        builder = type_obj.mutable_copy()
        if is_const:
            builder.const = True
        if is_volatile:
            builder.volatile = True
        return builder.immutable_copy()
    except Exception:
        return type_obj


def _named_type(components, is_const, is_volatile):
    text = "::".join(components)
    if not text:
        raise _MangleError("empty named type")
    build = lambda w, n=list(components), c=is_const, v=is_volatile: (
        Type.named_type_reference(
            bn.NamedTypeReferenceClass.UnknownNamedTypeClass,
            QualifiedName(n), const=c, volatile=v))
    return _Ty(text, build)


def _signed_prefix(is_signed, is_unsigned):
    return (("signed " if is_signed else "") +
            ("unsigned " if is_unsigned else ""))


def _parse_type(cur, arg_level):
    """One type, at the position of its first character.

    `arg_level` is true only for the immediate members of a function argument
    list, where a lone `v` means "no arguments" and prints as nothing.
    """
    is_const = is_volatile = is_signed = is_unsigned = False
    closure = False
    while True:
        c = cur.peek()
        if c == "u":
            cur.take()
            is_unsigned = True
        elif c == "z":
            cur.take()
            is_signed = True
        elif c == "x":
            cur.take()
            is_const = True
        elif c == "w":
            cur.take()
            is_volatile = True
        elif c == "y":
            cur.take()
            if cur.take() not in ("f", "n"):
                raise _MangleError("malformed __closure type")
            closure = True
        else:
            break

    c = cur.peek()
    if c.isdigit():
        # Length-prefixed name.  The body is a whole qualified name and may
        # itself contain `@` separators and `%template%` sections, so it is
        # re-parsed rather than copied.
        length = 0
        while cur.peek().isdigit():
            length = length * 10 + int(cur.take())
        body = cur.s[cur.i:cur.i + length]
        if len(body) != length:
            raise _MangleError("truncated length-prefixed name")
        cur.i += length
        inner = _parse_name(_Cursor(body))
        # Borland deliberately omits cv qualifiers on named types here; the
        # argument list prints them instead (BCB-265738).
        result = _named_type(inner.components, is_const, is_volatile)
        return _with_closure(result, closure)

    tname = None
    if c in _PRIMITIVES:
        cur.take()
        tname = _PRIMITIVES[c]
    elif c == "C":
        cur.take()
        tname = {"s": "char16_t", "i": "char32_t"}.get(cur.take())
        if tname is None:
            raise _MangleError("unknown wide character type")
    elif c in ("M", "r", "h", "p"):
        return _with_closure(
            _parse_indirection(cur, is_const, is_volatile), closure)
    elif c == "a":
        result = _parse_array(cur)
    elif c == "q":
        result = _parse_function(cur)
    elif c in (_ARGLIST, _TMPLCODE):
        # A template argument list ends here; the caller sorts it out.
        raise _MangleError("type expected, found %r" % c)
    else:
        raise _MangleError("unknown type code %r" % c)

    if tname is not None:
        build = _primitive_builder(tname, is_signed, is_unsigned)
        if build is not None and (is_const or is_volatile):
            build = lambda w, b=build, c=is_const, v=is_volatile: \
                _requalify(b(w), c, v)
        # A lone `v` in an argument list means "takes no arguments"; the
        # reference tool prints nothing for it.
        text = "" if (arg_level and tname == "void") else (
            ("const " if is_const else "") +
            ("volatile " if is_volatile else "") +
            _signed_prefix(is_signed, is_unsigned) + tname)
        return _with_closure(
            _Ty(text, build, is_void=(tname == "void"),
                is_ellipsis=(tname == "...")), closure)

    suffix = ((" const" if is_const else "") +
              (" volatile" if is_volatile else ""))
    if suffix:
        result = _Ty(result.text + suffix, result._build, func=result.func)
    return _with_closure(result, closure)


def _with_closure(ty, closure):
    if not closure:
        return ty
    return _Ty("__closure " + ty.text, ty._build, ty.is_void, ty.is_ellipsis,
               ty.func)


def _parse_indirection(cur, is_const, is_volatile):
    """Pointer `p`, reference `r`, rvalue reference `h`, member pointer `M`."""
    code = cur.peek()
    owner = None
    if code == "M":
        cur.take()
        owner = _parse_type(cur, False)
        # A member pointer's own cv qualifiers sit after the class type.
        if cur.peek() == "x":
            cur.take()
            is_const = True
        elif cur.peek() == "w":
            cur.take()
            is_volatile = True
    else:
        cur.take()

    inner = _parse_type(cur, False)

    if inner.func is not None:
        ret, params, varargs, _conv = inner.func
        marker = {"p": "*", "M": "*", "r": "&", "h": "&&"}[code]
        if owner is not None:
            marker = owner.text + "::" + marker
        args = ", ".join(p.text for p in params if not p.is_void)
        if varargs:
            args = (args + ", ..." if args else "...")
        text = "%s (%s)(%s)" % (ret.text if ret is not None else "void",
                                marker, args)
    elif code == "p":
        text = inner.text + " *"
    elif code == "r":
        text = inner.text + "&"
    elif code == "h":
        text = inner.text + "&&"
    else:
        text = "%s %s::*" % (inner.text, owner.text if owner else "?")

    if code == "M":
        # A pointer to member is not a pointer: it is an offset, and Binary
        # Ninja has no type for it.  Spell it, but claim no type.
        return _Ty(text)

    ref = {
        "p": bn.ReferenceType.PointerReferenceType,
        "r": bn.ReferenceType.ReferenceReferenceType,
        "h": bn.ReferenceType.RValueReferenceType,
    }[code]

    def build(width, inner=inner, ref=ref, c=is_const, v=is_volatile):
        target = inner.binja(width)
        if target is None:
            return None
        return Type.pointer_of_width(width, target, const=c, volatile=v,
                                     ref_type=ref)

    return _Ty(text, build)


def _parse_array(cur):
    dims = []
    while True:
        cur.expect("a")
        size = cur.read_until(_ARGLIST)
        cur.expect(_ARGLIST)
        dims.append("" if size == "0" else size)
        if cur.peek() != "a":
            break
    element = _parse_type(cur, False)
    text = element.text + "".join("[%s]" % d for d in dims)

    def build(width, element=element, dims=list(dims)):
        result = element.binja(width)
        if result is None:
            return None
        for d in reversed(dims):
            result = Type.array(result, int(d) if d.isdigit() else 0)
        return result

    return _Ty(text, build)


def _parse_function(cur):
    """`q` [`q` conv] args [`$` return-type].

    The convention loop is the reference's: a bare `q` is the compiler's
    default (cdecl), and each following `q` introduces one convention letter.
    """
    cur.expect("q")
    conv = None
    while cur.peek() == "q":
        cur.take()
        conv = cur.take()
    if conv is not None and conv not in _CALLCONV:
        raise _MangleError("unknown calling convention %r" % conv)
    spelling, cc_name = _CALLCONV[conv] if conv else _DEFAULT_CALLCONV

    params = _parse_args(cur, _ARGLIST)
    ret = None
    if cur.peek() == _ARGLIST:
        cur.take()
        ret = _parse_type(cur, False)

    real = [p for p in params if not p.is_void and not p.is_ellipsis]
    varargs = any(p.is_ellipsis for p in params)
    args = ", ".join(p.text for p in real)
    if varargs:
        args = (args + ", ..." if args else "...")
    text = "%s%s(%s)" % (ret.text + " " if ret is not None else "",
                         spelling + " " if spelling else "", args)

    def build(width, ret=ret, real=list(real), cc_name=cc_name,
              varargs=varargs):
        return _build_function(width, ret, real, cc_name, varargs, None)

    return _Ty(text, build, func=(ret, params, varargs, conv))


def _build_function(width, ret, params, cc_name, varargs, extra_first):
    """Assemble the Binary Ninja function type, or None if anything is
    unknown."""
    cc = _calling_convention(cc_name)
    if cc is None:
        return None
    arg_types = []
    for name, ty in (extra_first or []):
        arg_types.append((name, ty))
    for p in params:
        t = p.binja(width)
        if t is None:
            return None
        arg_types.append(t)
    ret_type = ret.binja(width) if ret is not None else None
    if ret_type is None:
        # The scheme only encodes a return type for template specialisations.
        # Emitting void at zero confidence keeps analysis' own answer, which
        # would otherwise be overwritten by a guess the symbol never made.
        ret_type = Type.void().with_confidence(0)
    return Type.function(ret_type, arg_types, cc, variable_arguments=varargs)


_CC_CACHE = {}


def _calling_convention(name):
    """The x86 convention by name, cached; None when the platform lacks it."""
    if name is None:
        return None
    if name in _CC_CACHE:
        return _CC_CACHE[name]
    result = None
    try:
        arch = bn.Architecture["x86"]
        for cc in arch.calling_conventions.values():
            if cc.name == name:
                result = cc
                break
    except Exception:
        result = None
    _CC_CACHE[name] = result
    return result


def _base36(ch):
    try:
        return int(ch, 36)
    except ValueError:
        raise _MangleError("bad backreference index %r" % ch)


def _parse_args(cur, end, template=False):
    """An argument list, stopping at `end` or at the end of the string.

    Every argument is remembered so that `t<n>` backreferences -- the
    mangler's way of saying "same type as argument n" -- can be resolved.
    """
    out = []
    table = []
    while True:
        c = cur.peek()
        if c == "" or c == end:
            break
        start = cur.i
        prefix = ""
        while cur.peek() in ("x", "w"):
            prefix += "const " if cur.take() == "x" else "volatile "
        if cur.peek() == "t":
            cur.take()
            index = _base36(cur.take()) - 1
            if not 0 <= index < len(table):
                raise _MangleError("backreference out of range")
            ty = table[index].prefixed(prefix)
        else:
            cur.i = start
            ty = _parse_type(cur, not template)
            ty = ty.prefixed(prefix)
        if template and cur.peek() == _ARGLIST:
            ty = _parse_nontype_argument(cur, start)
        table.append(ty)
        out.append(ty)
    return out


def _parse_nontype_argument(cur, arg_start):
    """A template's non-type argument: the encoded type, then a literal value.

    The type is thrown away -- `us$i0$` is "unsigned short, value 0" and only
    the 0 is printed -- which is why this replaces the argument already parsed.
    """
    cur.expect(_ARGLIST)
    kind = cur.take()
    terminator = ""
    if kind == "T":
        terminator = ">"
        kind = "i"
    if kind == "i" and cur.s[arg_start:arg_start + 5] == "4bool":
        value = "false" if cur.take() == "0" else "true"
    elif kind == "m":
        value = cur.read_until(_ARGLIST + _TMPLCODE) + "::*"
        if cur.peek() == _ARGLIST:
            cur.take()
            value += cur.read_until(_ARGLIST + _TMPLCODE)
    elif kind in ("i", "j", "g", "e"):
        value = cur.read_until(_ARGLIST + _TMPLCODE)
    else:
        raise _MangleError("unknown template argument kind %r" % kind)
    if terminator:
        value = "<type " + value + terminator
    if cur.peek() == _ARGLIST:
        cur.take()
    return _Ty(value)


def _parse_delphi4_args(cur, end):
    """The kind-tagged argument form used by Delphi's own four templates.

    Each argument is `<kind><encoding>`; `t` is a plain type, everything else
    is a compile-time constant whose encoded type is decoded and discarded.
    """
    out = []
    while True:
        c = cur.peek()
        if c == "" or c == end:
            break
        cur.take()
        kind = c
        terminator = ""
        if kind == "T":
            terminator = ">"
            kind = "i"
        if kind == "t":
            out.append(_parse_type(cur, False))
        elif kind in ("i", "j", "g", "e", "m"):
            if kind == "i" and cur.s[cur.i:cur.i + 5] == "4bool":
                _parse_type(cur, False)
                cur.expect(_ARGLIST)
                out.append(_Ty("false" if cur.take() == "0" else "true"))
            else:
                _parse_type(cur, False)
                cur.expect(_ARGLIST)
                value = cur.read_until(_ARGLIST + _TMPLCODE)
                if kind == "m":
                    value += "::*"
                    if cur.peek() == _ARGLIST:
                        cur.take()
                        value += cur.read_until(_ARGLIST + _TMPLCODE)
                if terminator:
                    value = "<type " + value + terminator
                out.append(_Ty(value))
        else:
            raise _MangleError("unknown Delphi template argument kind %r" % c)
        if cur.peek() != end:
            cur.expect(_ARGLIST)
    return out


def _parse_template(cur):
    """`%` name `$` args `%`, already past the opening `%`."""
    delphi4 = _DELPHI4_TEMPLATES.match(cur.rest()) is not None
    base = _parse_name(cur, template_name=True)
    name = "::".join(base.components)
    cur.expect(_ARGLIST)
    args = (_parse_delphi4_args(cur, _TMPLCODE) if delphi4
            else _parse_args(cur, _TMPLCODE, template=True))
    cur.expect(_TMPLCODE)
    inner = ", ".join(a.text for a in args)
    # Keep `< <` and `> >` apart the way the reference tool does, so nested
    # templates do not come out spelled as shift operators.
    lead = " " if name.endswith("<") else ""
    trail = " " if inner.endswith(">") else ""
    return "%s<%s%s%s>" % (name, lead, inner, trail)


# --------------------------------------------------------------------- names

class _Name(object):
    """The name half of a symbol: its qualified components and what it is."""

    def __init__(self):
        self.components = []
        self.kind = "data"
        self.vtable_flags = []
        self.descriptor = None

    def absorb(self, inner, prefix):
        """Append a nested name, marking where the decoration was found.

        The prefix belongs to the first component of the nested name, not to
        the whole symbol: `@Sysinit@@InitExe$...` is `Sysinit` qualifying
        `__linkproc__ InitExe`, not `__linkproc__ Sysinit::InitExe`.
        """
        components = list(inner.components)
        if components:
            components[0] = prefix + components[0]
        else:
            components = [prefix.rstrip()]
        self.components.extend(components)
        self.kind = inner.kind
        self.descriptor = inner.descriptor


def _parse_name(cur, template_name=False):
    info = _Name()
    while True:
        c = cur.peek()

        if c.isdigit():
            # A digit where a name should be is the virtual table flag byte.
            flags = int(cur.take()) + 1
            for bit, label in ((1, "huge"), (2, "fastthis"), (4, "rtti")):
                if flags & bit:
                    info.vtable_flags.append(label)
            info.kind = "vtable"
            c = cur.peek()
            if c not in ("", _ARGLIST):
                raise _MangleError("stray digit in name")

        if c == "#":
            _parse_virdef_flag(cur, info)
            return info
        if c == _QUALIFIER:
            # An empty qualifier means a linker-generated helper.
            cur.take()
            info.absorb(_parse_name(cur), "__linkproc__ ")
            return info
        if c == "_" and cur.peek(1) == _ARGLIST:
            _parse_special_table(cur, info)
            return info
        if c == _TMPLCODE:
            cur.take()
            info.components.append(_parse_template(cur))
        elif c == _ARGLIST:
            if template_name:
                return info
            component = _parse_special_name(cur, info)
            if component is None:
                return info
            if component:
                info.components.append(component)
        elif c == "":
            break
        else:
            info.components.append(cur.read_until(_QUALIFIER + _ARGLIST))

        c = cur.peek()
        if c != _QUALIFIER:
            break
        cur.take()
        if cur.eof:
            # `@Unit@Class@` with nothing after it is the class' vtable.
            info.kind = "vtable"
            break
    return info


def _parse_virdef_flag(cur, info):
    """`#$cf$@name` -- the virtual-function-definition flag for `name`."""
    cur.expect("#")
    for ch in "$cf$@":
        cur.expect(ch)
    info.absorb(_parse_name(cur), "__vdflg__ ")


def _parse_special_table(cur, info):
    """`_$XX...$@name` -- friend list, catch handler table and friends."""
    cur.expect("_")
    cur.expect(_ARGLIST)
    code = ""
    while cur.peek().isupper():
        code += cur.take()
    cur.expect(_ARGLIST)
    cur.expect(_QUALIFIER)
    info.absorb(_parse_name(cur),
                "__%s__ " % _SPECIAL_TABLES.get(code[:2], code or "tbl"))
    info.kind = "table"


def _parse_special_name(cur, info):
    """A `$`-introduced member name.

    Returns the component to append, "" when the caller must synthesise it
    (constructors and destructors take the enclosing class' name, which is not
    repeated in the encoding), or None when the whole symbol is consumed.
    """
    cur.expect(_ARGLIST)
    c = cur.take()

    if c == "x":
        # `$xp$` / `$xt$` -- a type descriptor for the type that follows.
        if cur.take() not in ("p", "t"):
            raise _MangleError("malformed type descriptor")
        cur.expect(_ARGLIST)
        info.kind = "tpdsc"
        info.descriptor = _parse_type(cur, False)
        return None

    if c == "b":
        tag = cur.take()
        op_start = cur.i - 1
        if tag in ("c", "d") and cur.peek() == "t" and cur.peek(1) == "r":
            cur.take()
            cur.take()
            if cur.peek() != _ARGLIST:
                raise _MangleError("malformed constructor name")
            info.kind = "ctor" if tag == "c" else "dtor"
            return ""
        cur.i = op_start
        op = cur.read_until(_ARGLIST)
        if op in _CLASS_INIT:
            info.kind = "operator"
            return _CLASS_INIT[op]
        info.kind = "operator"
        return "operator " + _OPERATORS.get(op, "?%s?" % op)

    if c == "o":
        info.kind = "conversion"
        target = _parse_type(cur, False)
        if cur.peek() != _ARGLIST:
            raise _MangleError("malformed conversion operator")
        return "operator " + target.text

    if c in ("v", "d"):
        return _parse_thunk(cur, info, c)

    raise _MangleError("unknown special name $%s" % c)


def _parse_thunk(cur, info, tag):
    kind = cur.take()
    if tag == "v" and kind == "s":
        if cur.take() not in ("f", "n"):
            raise _MangleError("malformed virdef thunk")
        info.kind = "thunk"
        return "__vdthk__"
    if kind != "c":
        raise _MangleError("unknown thunk $%s%s" % (tag, kind))
    index = cur.take()
    if not index.isdigit():
        raise _MangleError("malformed thunk index")
    cur.expect(_ARGLIST)
    fields = [index]
    for _ in range(3):
        fields.append(cur.read_until(_ARGLIST))
        if cur.peek() == _ARGLIST:
            cur.take()
    info.kind = "thunk"
    return "__thunk__ [%s]" % ",".join(fields)


# ------------------------------------------------------------------- results

class BorlandName(object):
    """A decoded symbol: qualified name, what kind of thing it is, its type."""

    def __init__(self, name, kind, components, signature=None,
                 convention=None, parameters=None, return_type=None,
                 variable_arguments=False, self_class=None, vtable_flags=None):
        self.name = name
        self.kind = kind
        self.components = components
        self.signature = signature
        self.convention = convention          # the raw scheme letter, or None
        self.parameters = parameters or []
        self.return_type = return_type
        self.variable_arguments = variable_arguments
        self.self_class = self_class
        self.vtable_flags = vtable_flags or []

    def text(self):
        """The whole declaration, spelled the way Borland's tools spell it."""
        if self.signature is None:
            return self.name
        ret, conv, args = self.signature
        head = (ret + " " if ret else "") + (conv + " " if conv else "")
        return "%s%s(%s)" % (head, self.name, args)

    def __repr__(self):
        return "<BorlandName %s>" % self.text()


def _finish_name(info, components):
    """Fill in the names the encoding leaves implicit."""
    if info.kind == "ctor" or info.kind == "dtor":
        if len(components) < 1:
            components = components + ["unknown"]
        else:
            base = components[-1]
            components = components + [("~" + base) if info.kind == "dtor"
                                       else base]
    elif info.kind == "vtable":
        components = components + ["`vtable'"]
    return components


def _descriptor_components(ty):
    """Where to hang a type descriptor's name.

    A descriptor for a plain named type reads best as a member of that type
    (`Discomp::TFlagType::__tpdsc__`); one for a decorated type (a pointer, a
    specialised template) has no such home and keeps its spelling intact.
    """
    text = ty.text
    if _PLAIN_QUALIFIED.match(text):
        return text.split("::") + ["__tpdsc__"]
    return ["__tpdsc__ " + text]


def demangle_name(mangled):
    """Decode one Borland symbol into a `BorlandName`, or None if it is not
    one.

    Never raises.  A name whose argument list fails to parse still comes back
    with its qualified name filled in and no signature, because half an answer
    beats none for a symbol table.
    """
    if not isinstance(mangled, str) or not _looks_mangled(mangled):
        return None

    body = mangled[1:] if mangled[0] == _QUALIFIER else mangled
    if not body:
        return None

    cur = _Cursor(body)
    try:
        info = _parse_name(cur)
    except _MangleError:
        return None

    if info.kind == "tpdsc" and info.descriptor is not None:
        components = _descriptor_components(info.descriptor)
    else:
        components = _finish_name(info, list(info.components))
    components = [c for c in components if c]
    if not components:
        return None

    name = "::".join(components)
    if cur.peek() != _ARGLIST:
        return BorlandName(name, info.kind, components,
                           vtable_flags=info.vtable_flags)

    # Everything from here is best-effort: a name plus a bad signature is
    # worse than a name alone, so any failure drops the signature only.
    saved = cur.i
    try:
        cur.take()
        func = _parse_type(cur, False)
        if func.func is None or not cur.eof:
            raise _MangleError("trailing junk after signature")
    except _MangleError:
        cur.i = saved
        return BorlandName(name, info.kind, components,
                           vtable_flags=info.vtable_flags)

    ret, params, varargs, conv = func.func
    spelling = _CALLCONV[conv][0] if conv else _DEFAULT_CALLCONV[0]
    real = [p for p in params if not p.is_void and not p.is_ellipsis]
    args = ", ".join(p.text for p in real)
    if varargs:
        args = (args + ", ..." if args else "...")
    return BorlandName(
        name, "function" if info.kind == "data" else info.kind, components,
        signature=(ret.text if ret is not None else "", spelling, args),
        convention=conv, parameters=real, return_type=ret,
        variable_arguments=varargs, self_class=_self_class(components),
        vtable_flags=info.vtable_flags)


def _self_class(components):
    """The class whose Self this routine receives, if it takes one.

    The mangling does not distinguish `Unit::Class::Method` from a routine
    nested any other way, so this leans on Delphi's naming conventions: unit
    names are ordinary words (`Sysutils`, `Vcl.Forms`), classes, interfaces
    and exception types are `TFoo`, `IFoo`, `EFoo`.  When the shape is not
    recognisable the caller emits no Self and no signature rather than one
    with every argument shifted by a register.
    """
    if len(components) < 3:
        return None
    owner = components[-2]
    if not _CLASSLIKE.match(owner):
        return None
    return components[:-1]


# ------------------------------------------------------------- Binary Ninja

class BorlandDemangler(Demangler):
    """Binary Ninja demangler for Borland / C++Builder / Delphi symbols."""

    name = DEMANGLER_NAME

    #: Delphi passes Self to instance methods in EAX, ahead of the arguments
    #: the mangling lists.  Recovering it is a naming heuristic (see
    #: `_self_class`), so it can be switched off wholesale.
    synthesize_self = True

    def is_mangled_string(self, name):
        try:
            return _looks_mangled(name)
        except Exception:
            return False

    def demangle(self, name, config):
        # `_demangle` is the base class' ctypes callback; keep clear of it.
        try:
            return self._decode(name, config)
        except Exception:
            return None

    def _decode(self, name, config):
        decoded = demangle_name(name)
        if decoded is None:
            return None
        qualified = QualifiedName(decoded.components)
        width = _pointer_width(config)
        return DemangleResult(self._type_for(decoded, width), qualified)

    def _type_for(self, decoded, width):
        if decoded.signature is None:
            return None
        if decoded.kind in ("ctor", "dtor"):
            # Delphi slips an allocate/free flag into DL ahead of the declared
            # arguments, and only for TObject descendants.  Since the mangling
            # does not say whether this class is one, every argument position
            # after the first is a coin toss: name it, do not type it.
            return None
        cc_name = (_CALLCONV[decoded.convention][1] if decoded.convention
                   else _DEFAULT_CALLCONV[1])
        if cc_name is None:
            # A convention Binary Ninja cannot model (`__fortran`, `__syscall`,
            # ...): the arguments would land in the wrong places, so say
            # nothing about the type at all.
            return None
        extra = None
        if self.synthesize_self and decoded.self_class:
            owner = _named_type(decoded.self_class, False, False)
            target = owner.binja(width)
            if target is None:
                return None
            extra = [("Self", Type.pointer_of_width(width, target))]
        return _build_function(width, decoded.return_type, decoded.parameters,
                               cc_name, decoded.variable_arguments, extra)


def _pointer_width(config):
    try:
        platform = getattr(config, "platform", None)
        if platform is not None and platform.arch is not None:
            return platform.arch.address_size
    except Exception:
        pass
    return 4


def _looks_mangled(name):
    """Conservative test: only names that cannot belong to another scheme.

    Borland symbols start with `@`, or are a bare template section wrapped in
    `%`.  Microsoft's fastcall decoration `@name@12` shares the leading `@`
    and is explicitly excluded; MSVC (`?`), Itanium (`_Z`), Rust, D and Swift
    names never begin with either character.
    """
    if not name or len(name) < 2:
        return False
    if name[0] not in (_QUALIFIER, _TMPLCODE):
        return False
    if _MSVC_FASTCALL.match(name):
        return False
    return _CANDIDATE.match(name) is not None


def register():
    """Register the demangler, once per process.

    Newly registered demanglers take priority over the built-in ones, which is
    harmless here: `is_mangled_string` declines everything that is not a
    Borland symbol, so no other demangler loses a name it would have claimed.
    """
    if DEMANGLER_NAME in Demangler:
        return True
    return BorlandDemangler.register()
