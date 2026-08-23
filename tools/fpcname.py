"""Free Pascal symbol demangling.

The scheme is `compiler/symdef.pas`, not the published documentation, which is
stale.  `tprocdef.defaultmangledname` is

    make_mangledname('', procsym.owner, procsym.name) + mangledprocparanames(...)

and `make_mangledname` composes at most four parts:

    [typeprefix + '_$'] + unitname + ['$_$' + prefix] + ['_$$_' + suffix]

where an object or record scope contributes `<objname>_$_` to *prefix* and a
nested routine contributes `<procname><params>` (joined with `_` as the nesting
deepens).  `mangledprocparanames` then appends `'$' + <TYPE>` per non-hidden
parameter and `'$$' + <TYPE>` for a non-void return, `<TYPE>` being the
**uppercased declared type name**.  So

    SYSUTILS_$$_STRCOMP$PCHAR$PCHAR$$LONGINT
      -> unit SYSUTILS, StrComp(PChar, PChar): LongInt
    SYSTEM$_$TOBJECT_$__$$_DESTROY
      -> unit SYSTEM, class TOBJECT, Destroy
    SYSUTILS$_$EXPANDFILENAMECASE$UNICODESTRING$TFILENAMECASEMATCH$$UNICODESTRING_$$_TRYCASE$crc6409A25D
      -> a routine nested inside ExpandFileNameCase, parameters hashed away

Two things are *not* recoverable from the symbol.  Parameter lists longer than
a threshold collapse to `$crc<hex32>` (3.2.2) or `$h<base64 fnv64>` (trunk), and
the whole name is uppercased -- `symdef.pas` mangles `procsym.name`, never
`realname`.  Case is restored separately, from the companion `.ppu`; see
`CaseOracle`.

Hidden parameters are absent from the mangled name by construction
(`vo_is_hidden_para` is skipped), so `hidden_params` reconstructs the ones the
ABI actually passes -- `$self`, `$vmt`, `$parentfp` and the hidden `$result`
that `paramanager.ret_in_param` forces for managed return types.  Their
positions come from the `paranr_*` constants in `symconst.pas`, with the i386
`register` convention's left-to-right push putting `$result` last
(`pushleftright_pocalls = [pocall_register, pocall_pascal]`).
"""

import collections
import re

from . import naming

# `<name>_$` at the start, but not `<unit>_$$_<member>`: the typeprefix marker
# is a single `$`.  A unit name can never contain `$`, so this is unambiguous.
_TYPEPREFIX = re.compile(r"^([A-Za-z0-9_]+)_\$(?!\$)")

_CRC_PARAMS = re.compile(r"^crc[0-9A-Fa-f]{8}$")
_FNV_PARAMS = re.compile(r"^h[A-Za-z0-9_$]{1,16}$")

# Data, not code: these prefixes mark VMTs, RTTI blobs, resource strings and
# similar. Kept as a set so a caller can tell a routine from a table.
DATA_TYPEPREFIXES = frozenset((
    "VMT", "RTTI", "RTTIL", "RESSTR", "THREADVARLIST", "INTF", "SYMS",
    "TYPEINFO", "TC", "DBG",
))

_IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{2,63}")


class Name(object):
    """One demangled symbol."""

    __slots__ = ("mangled", "typeprefix", "unit", "scopes", "classes",
                 "member", "params", "ret", "hashed", "nested")

    def __init__(self, mangled, typeprefix=None, unit=None, scopes=(),
                 classes=0, member="", params=(), ret=None, hashed=False,
                 nested=False):
        self.mangled = mangled
        self.typeprefix = typeprefix
        self.unit = unit
        self.scopes = list(scopes)      # class names then enclosing routines
        self.classes = classes          # how many leading scopes are classes
        self.member = member
        self.params = list(params)      # uppercase declared type names
        self.ret = ret
        self.hashed = hashed            # parameter list collapsed to a hash
        self.nested = nested            # routine local to another routine

    @property
    def is_method(self):
        """A routine nested inside a method is not itself a method: it takes a
        frame pointer, not a `Self`."""
        return self.classes > 0 and not self.nested

    def __repr__(self):
        return "<Name %s>" % self.qualified()

    def qualified(self, case=None):
        """`Unit::Class::Member`, through `naming` so the FPC libraries read
        exactly like the Delphi ones.  Nesting can run deeper than three
        parts, so the scopes collapse into the class position."""
        fix = case.fix if case is not None else (lambda s: s)
        scopes = naming.SEP.join(fix(s) for s in self.scopes if s)
        name = naming.qualify(fix(self.unit) if self.unit else None,
                              scopes,
                              fix(self.member) if self.member else None)
        if self.typeprefix and self.typeprefix in DATA_TYPEPREFIXES:
            name = naming.qualify(name, None, self.typeprefix.lower())
        return name or self.mangled


def demangle(mangled, unit=None):
    """Best-effort structural parse.  Never raises; unparseable names come
    back as a bare member, which is the right answer for compiler helpers
    like `FPC_MOVE` that carry no unit at all.

    `unit` is the name of the object file the symbol came from.  It is only
    consulted for the pre-3.0 mangling, where the part separator is a plain
    `_` and the unit name is the one boundary nothing else can locate.
    """
    s = mangled
    if not s or s.startswith("_$dll$"):
        return Name(mangled, member=mangled)

    # `$_$` and `_$$_` are the 3.0-and-later part separators, and neither can
    # occur in a 2.6.x name -- its separators are `_` and `_$_`. So their
    # presence, tested before anything is stripped, is what picks the scheme.
    if "$_$" not in s and "_$$_" not in s:
        legacy = _demangle_legacy(mangled, s, unit)
        if legacy is not None:
            return legacy
        return Name(mangled, member=s)

    typeprefix = None
    m = _TYPEPREFIX.match(s)
    if m:
        typeprefix = m.group(1)
        s = s[m.end():]

    i_obj = s.find("$_$")
    i_sfx = s.find("_$$_")
    if i_obj < 0 and i_sfx < 0:
        return Name(mangled, typeprefix=typeprefix, member=s)

    if i_obj >= 0 and (i_sfx < 0 or i_obj < i_sfx):
        unit = s[:i_obj]
        rest = s[i_obj + 3:]
        i_sfx = rest.find("_$$_")
        if i_sfx < 0:
            return Name(mangled, typeprefix=typeprefix, unit=unit, member=rest)
        prefix, suffix = rest[:i_sfx], rest[i_sfx + 4:]
    else:
        unit = s[:i_sfx]
        prefix, suffix = "", s[i_sfx + 4:]

    if unit.startswith("P$"):           # program, not unit
        unit = unit[2:]

    scopes, nclasses, nested = _split_prefix(prefix)
    member, params, ret, hashed = _split_suffix(suffix)
    return Name(mangled, typeprefix=typeprefix, unit=unit, scopes=scopes,
                classes=nclasses, member=member, params=params, ret=ret,
                hashed=hashed, nested=nested)


def _demangle_legacy(mangled, stripped, unit):
    """The FPC 2.6.x scheme, where every part is joined with a plain `_`.

    `make_mangledname` there reads

        [typeprefix + '_'] + unitname + ['_' + prefix] + ['_' + suffix]

    with the same `<objname>_$_` for object scopes.  A plain `_` is also a
    perfectly good character in an identifier, so the only reliable boundary
    is the unit name -- which the caller knows, because it is the name of the
    object file the symbol was read from.  Without that hint this returns
    `None` and the caller falls back to treating the symbol as a bare name.

        CLASSES_TSTREAM_$__READDWORD$$LONGWORD    Classes::TStream::ReadDWord
        CLASSES_DELETEINSTBLOCKLIST               Classes::DeleteInstBlockList
    """
    if not unit:
        return None
    marker = unit.upper() + "_"
    head = stripped.upper()
    if head.startswith(marker):
        typeprefix, rest = None, stripped[len(marker):]
    else:
        cut = head.find("_" + marker)
        if cut < 0:
            return None
        typeprefix = stripped[:cut]
        rest = stripped[cut + 1 + len(marker):]
    if not rest:
        return None

    scopes, nclasses, nested = [], 0, False
    if "_$_" in rest:
        parts = rest.split("_$_")
        tail = parts.pop()
        scopes = parts
        nclasses = len(scopes)
        if tail.startswith("_"):
            suffix = tail[1:]               # a plain method
        else:
            tail, suffix, nested = _legacy_split_nested(tail)
            if nested and tail:
                scopes.append(tail)
    else:
        outer, suffix, nested = _legacy_split_nested(rest)
        if nested and outer:
            scopes.append(outer)

    member, params, ret, hashed = _split_suffix(suffix)
    return Name(mangled, typeprefix=typeprefix, unit=unit.upper(),
                scopes=scopes, classes=nclasses, member=member, params=params,
                ret=ret, hashed=hashed, nested=nested)


def _legacy_split_nested(text):
    """Separate an enclosing routine from the routine nested in it.

    `OBJECTTEXTTOBINARY$TSTREAM$TSTREAM_PROCESSVALUE` is an enclosing routine
    with its parameter types, then `_`, then the nested one.  The split point
    is the last `_` *after* the last `$`: anything before that is still part
    of the enclosing routine's parameter list, and a `_` with no `$` before it
    anywhere is just a `_` in an identifier.
    """
    last_dollar = text.rfind("$")
    if last_dollar < 0:
        return "", text, False
    cut = text.find("_", last_dollar)
    if cut < 0:
        return "", text, False
    return text[:cut].split("$", 1)[0], text[cut + 1:], True


def _split_prefix(prefix):
    """`TFOO_$_TBAR_$_<nested chain>` -> (scopes, class count, nested).

    The nested chain is `<outerproc><params>` joined with `_` as nesting
    deepens, and both the params and the `_` join are ambiguous to split, so
    only the outermost routine name is recovered.  These are file-local
    helpers; the class scopes, which are what anyone reads, are exact.
    """
    if not prefix:
        return [], 0, False
    parts = prefix.split("_$_")
    tail = parts.pop()                  # '' for a plain method
    scopes = [p for p in parts if p]
    nclasses = len(scopes)
    nested = False
    if tail:
        nested = True
        outer = tail.split("$", 1)[0]
        if outer:
            scopes.append(outer)
    return scopes, nclasses, nested


def _split_suffix(suffix):
    """`NAME$PARAM$PARAM$$RET` -> (name, params, ret, hashed)."""
    if not suffix:
        return "", [], None, False
    # Operator overloads mangle as `$assign`, `$greater_or_equal`, ...
    if suffix.startswith("$"):
        rest = suffix[1:]
        cut = rest.find("$")
        if cut < 0:
            return "$" + rest, [], None, False
        member, tokens = "$" + rest[:cut], rest[cut:].split("$")[1:]
    else:
        tokens = suffix.split("$")
        member, tokens = tokens[0], tokens[1:]

    params, ret, hashed = [], None, False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "":                   # `$$` introduces the return type
            ret = tokens[i + 1] if i + 1 < len(tokens) else None
            i += 2
            continue
        if not params and (_CRC_PARAMS.match(tok) or
                           (tok.startswith("h") and _FNV_PARAMS.match(tok)
                            and not tok.isupper())):
            hashed = True
            i += 1
            continue
        params.append(tok)
        i += 1
    return member, params, ret, hashed


# -- hidden parameters ---------------------------------------------------

# `paramanager.ret_in_param` is true for every managed type and for records,
# arrays, sets and short strings -- but only the ones nameable from the
# mangled type name alone are claimed here.  A record type is spelled `TFoo`
# exactly like a class, and guessing wrong would shift every register
# parameter, so unknown `T*` names are left alone.
_RET_IN_PARAM = frozenset((
    "SHORTSTRING", "ANSISTRING", "RAWBYTESTRING", "UNICODESTRING",
    "WIDESTRING", "UTF8STRING", "UNICODESTRING", "STRING",
    "VARIANT", "OLEVARIANT",
))


def ret_in_param(ret):
    if not ret:
        return False
    r = ret.upper()
    return r in _RET_IN_PARAM or r.startswith("ARRAY_OF_")


def hidden_params(name, result_last=True):
    """The hidden parameters the ABI passes, as (before, after) lists.

    The lists go before and after the declared parameters.  Only the cases
    identifiable from the symbol are claimed:

    * `$parentfp` for a routine nested inside another (paranr_parentfp = 2).
    * `$self` for a method (paranr_self = 3).
    * `$vmt` for a constructor or destructor (paranr_vmt = 5).  A destructor
      is recognised by Object Pascal's universal `Destroy` spelling and a
      constructor by returning its own class from a `Create*` member; both are
      conventions rather than anything the mangling records.
    * `$result` when the return type is one `ret_in_param` forces into a
      parameter.  It normally takes `paranr_result = 4`, between `$self` and
      `$vmt` -- but `insert_funcret_para` has an i386-only branch giving it
      `paranr_result_leftright` for the `pushleftright_pocalls`, which include
      `pocall_register`.  So on i386 it lands *after* the declared parameters
      and everywhere else before them; `result_last` says which.
    """
    before, after = [], []
    if name.nested:
        before.append("parentfp")
    if name.is_method:
        before.append("self")
    result = ret_in_param(name.ret)
    if result and not result_last:
        before.append("result")
    if name.is_method:
        member = (name.member or "").upper()
        own = name.scopes[-1].upper() if name.scopes else ""
        ctor = member.startswith("CREATE") and (name.ret or "").upper() == own
        if member == "DESTROY" or ctor:
            before.append("vmt")
    if result and result_last:
        after.append("result")
    return before, after


# -- case restoration ----------------------------------------------------

class CaseOracle(object):
    """Recover the source spelling of an uppercased identifier.

    The mangled name is uppercase by construction, but the companion `.ppu`
    stores every symbol's `realname` verbatim.  Parsing a PPU properly means
    tracking a version-locked nested entry stream with deref tables, and the
    format churns every release -- so this reads the file as a bag of
    identifiers instead and keeps, per uppercased key, the spelling that looks
    most like source: mixed case beats all-lower beats all-upper, ties broken
    by frequency.  It is a heuristic, and a wrong guess costs only letter case
    in a name, never a wrong name.
    """

    def __init__(self):
        self._counts = collections.defaultdict(collections.Counter)
        self._cache = {}

    def add_file(self, path):
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            return 0
        return self.add_bytes(blob)

    def add_bytes(self, blob):
        n = 0
        for m in _IDENT.finditer(blob):
            word = m.group().decode("latin-1")
            self._counts[word.upper()][word] += 1
            n += 1
        self._cache.clear()
        return n

    @staticmethod
    def _rank(word):
        if not word.isupper() and not word.islower():
            return 2                    # SysUtils
        if word.islower():
            return 1                    # sysutils
        return 0                        # SYSUTILS

    def fix(self, word):
        # Only single-case words are guesses. A routine local to another
        # routine has no COFF symbol of its own on win32, so its name comes
        # from the section name, which the assembler writer lowercases -- both
        # spellings therefore need re-casing, and a word that already mixes
        # case is already the source spelling.
        if not word or not (word.isupper() or word.islower()):
            return word
        hit = self._cache.get(word)
        if hit is not None:
            return hit
        candidates = self._counts.get(word.upper())
        if not candidates:
            self._cache[word] = word
            return word
        best = max(candidates.items(),
                   key=lambda kv: (self._rank(kv[0]), kv[1]))[0]
        self._cache[word] = best
        return best

    def __len__(self):
        return len(self._counts)
