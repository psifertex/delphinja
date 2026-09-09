"""Read a Delphi runtime package (`.bpl`) as a knowledge base.

The fourth source in `tools/`, after IDR knowledge bases ([README.md](README.md)),
Free Pascal object files ([FPC.md](FPC.md)) and a modern binary's own extended
RTTI ([RTTI.md](RTTI.md)).  See [BPL.md](BPL.md) for what it buys and what it
costs.

A `.bpl` is an ordinary PE DLL that a Delphi installation builds out of the
same `.dcu` files a statically linked executable draws on, and it publishes
three things this needs:

* an **export table** naming every interface symbol the package contains, in
  the Borland mangling `demangler.py` already decodes completely -- so a name
  arrives with its unit, its class, its member and its full argument list;
* a **`PACKAGEINFO` resource** listing the units the package contains, spelled
  the way the compiler spells them (`System.SysUtils`, not `Sysutils`), which
  is the only place the namespace dots and the letter case survive;
* a **`.reloc` table**, which is read rather than reconstructed.  Nothing here
  stages an image or relinks a fixup: the code is already laid out, and
  Binary Ninja's PE loader already knows which bytes are relocatable.

That is the whole difference from `kb.py`.  A knowledge base holds detached
code dumps that `stage.py` has to reassemble into something analysable; a
package *is* the assembled thing.

Nothing in this module imports Binary Ninja beyond the demangler, and nothing
in it needs a Delphi installation.
"""

import collections
import importlib.util
import os
import struct

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


_MODULE = []


def _demangler():
    """`demangler.py` loaded from the file, not through the package.

    `import delphinja.demangler` runs the plugin's `__init__`, which registers
    the recovery workflow into the build process -- the very thing the note in
    README.md warns about.  The module itself is self-contained, so load it
    directly and leave the package alone.
    """
    if not _MODULE:
        spec = importlib.util.spec_from_file_location(
            "delphinja_demangler", os.path.join(_ROOT, "demangler.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULE.append(module)
    return _MODULE[0]


# ---------------------------------------------------------------- PE reading

class Package(object):
    """A `.bpl` read straight from the file: sections, exports, contained units."""

    def __init__(self, path):
        self.path = path
        self.b = open(path, "rb").read()
        b = self.b
        pe = struct.unpack_from("<I", b, 0x3C)[0]
        if b[pe:pe + 4] != b"PE\0\0":
            raise ValueError("%s is not a PE image" % path)
        coff = pe + 4
        self.machine = struct.unpack_from("<H", b, coff)[0]
        n_sections = struct.unpack_from("<H", b, coff + 2)[0]
        opt_size = struct.unpack_from("<H", b, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", b, opt)[0]
        if magic != 0x10B:
            raise ValueError("%s is not a PE32 image" % path)
        self.image_base = struct.unpack_from("<I", b, opt + 28)[0]
        n_dirs = struct.unpack_from("<I", b, opt + 92)[0]
        dirs = opt + 96
        self.directories = [struct.unpack_from("<II", b, dirs + 8 * i)
                            for i in range(n_dirs)]
        self.sections = []
        for i in range(n_sections):
            o = opt + opt_size + 40 * i
            self.sections.append(dict(
                name=b[o:o + 8].rstrip(b"\0").decode("latin-1"),
                vsize=struct.unpack_from("<I", b, o + 8)[0],
                vaddr=struct.unpack_from("<I", b, o + 12)[0],
                rsize=struct.unpack_from("<I", b, o + 16)[0],
                roff=struct.unpack_from("<I", b, o + 20)[0],
                flags=struct.unpack_from("<I", b, o + 36)[0]))

    def offset(self, rva):
        """File offset of an RVA, or None if it lands in uninitialised data."""
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
                delta = rva - s["vaddr"]
                return s["roff"] + delta if delta < s["rsize"] else None
        return None

    def section_of(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
                return s
        return None

    def _cstring(self, rva):
        o = self.offset(rva)
        if o is None:
            return None
        return self.b[o:self.b.index(b"\0", o)].decode("latin-1")

    def exports(self):
        """`[(mangled_name, virtual_address)]` for every named export.

        A package exports by name only -- the ordinal table exists but nothing
        links to a package by ordinal -- so an unnamed slot carries nothing
        this pipeline can use and is skipped.
        """
        rva, _ = self.directories[0]
        if not rva:
            return []
        o = self.offset(rva)
        n_names = struct.unpack_from("<I", self.b, o + 24)[0]
        a_func = self.offset(struct.unpack_from("<I", self.b, o + 28)[0])
        a_name = self.offset(struct.unpack_from("<I", self.b, o + 32)[0])
        a_ord = self.offset(struct.unpack_from("<I", self.b, o + 36)[0])
        out = []
        for i in range(n_names):
            name = self._cstring(struct.unpack_from("<I", self.b, a_name + 4 * i)[0])
            index = struct.unpack_from("<H", self.b, a_ord + 2 * i)[0]
            target = struct.unpack_from("<I", self.b, a_func + 4 * index)[0]
            if name and target:
                out.append((name, self.image_base + target))
        return out

    # -- resources ---------------------------------------------------------
    def _resource_dir(self, off, base, path, out):
        b = self.b
        n = (struct.unpack_from("<H", b, off + 12)[0]
             + struct.unpack_from("<H", b, off + 14)[0])
        for i in range(n):
            e = off + 16 + 8 * i
            name_field, data_field = struct.unpack_from("<II", b, e)
            if name_field & 0x80000000:
                o = base + (name_field & 0x7FFFFFFF)
                length = struct.unpack_from("<H", b, o)[0]
                name = b[o + 2:o + 2 + 2 * length].decode("utf-16-le")
            else:
                name = name_field
            if data_field & 0x80000000:
                self._resource_dir(base + (data_field & 0x7FFFFFFF), base,
                                   path + [name], out)
            else:
                o = base + data_field
                out.append((tuple(path + [name]),
                            struct.unpack_from("<I", b, o)[0],
                            struct.unpack_from("<I", b, o + 4)[0]))

    def resources(self):
        rva, _ = self.directories[2]
        if not rva:
            return []
        base = self.offset(rva)
        out = []
        self._resource_dir(base, base, [], out)
        return out

    def contains(self):
        """The units this package holds, spelled as the compiler spells them.

        `PACKAGEINFO` is the only spelling that survives compilation intact.
        The mangled export name normalises case and loses the namespace dots
        entirely -- `@System@Sysutils@...` for `System.SysUtils` -- so without
        this resource there is no way back to a name the other libraries and
        the plugin's own RTTI naming would produce.

        Each entry is a flags byte, a hash byte and a NUL-terminated name.
        """
        for path, rva, _ in self.resources():
            if not any(str(p).upper() == "PACKAGEINFO" for p in path):
                continue
            o = self.offset(rva)
            b = self.b
            p = o + 4                                    # skip the flags word
            groups = []
            for _ in range(2):                    # requires, then contains
                count = struct.unpack_from("<i", b, p)[0]
                p += 4
                names = []
                for _ in range(count):
                    p += 2                        # entry flags, name hash
                    end = b.index(b"\0", p)
                    names.append(b[p:end].decode("latin-1"))
                    p = end + 1
                groups.append(names)
            return groups[1]
        return []


# ------------------------------------------------------------------- naming

#: Components the mangling produces for a compiler helper, which the knowledge
#: bases and `naming.split_kb_name` both spell with a leading `@`.
_LINKPROC = "__linkproc__ "


def strip_arguments(component):
    """Drop a generic's argument list: `TList__1<TFoo *>` -> `TList__1`.

    The package instantiates the RTL's generics with the RTL's own types, and
    an application instantiates them with its own.  Where the two have the
    same layout the compiler emits the same code, so the body that says
    `TList<TAcceptValueItem>` here is the body an application uses for
    `TList<TAnythingElse>` -- and a signature naming the package's
    instantiation would be confidently wrong about every other one.

    The argument list is the only part that is wrong; `TList__1::InsertRange`
    is true of every instantiation that compiles to this code.  Dropping it
    also merges instantiations that folded into one body, which turns what
    would have been two names for one address into one name for one address.
    """
    out = []
    depth = 0
    for ch in component:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(depth - 1, 0)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


class Namer(object):
    """Turn a package's mangled exports into `Unit::Class::Member`.

    The mangling gives components but not their roles: `@System@Classes@
    TStrings@AddStrings` is four names in a row, and nothing in the string says
    the first two are one namespaced unit.  `PACKAGEINFO` does say, so the
    longest component prefix that spells a contained unit is the unit, and
    what follows is the class chain and the member.
    """

    def __init__(self, package):
        self.demangle = _demangler().demangle_name
        # Keyed on the lowercased dotted spelling; the value is the compiler's
        # own casing, which is what goes into the library.
        self.units = {}
        for unit in package.contains():
            self.units[unit.lower()] = unit

    def unit_of(self, components):
        """Split `components` into (unit, rest) at the longest unit prefix."""
        for n in range(min(len(components) - 1, 8), 0, -1):
            unit = self.units.get(".".join(components[:n]).lower())
            if unit is not None:
                return unit, components[n:]
        return None, components

    def name(self, mangled):
        """`Unit::Class::Member`, or None if this export cannot be trusted.

        Declined, and why:

        `tpdsc`, `data`, `vtable`
            not code.  A type descriptor and a VMT live in the code section of
            a Delphi image and analysis makes functions out of them, so they
            have to be refused by kind rather than by where they point.

        `ctor`
            Borland's mangling collapses every Delphi constructor to `$bctr`
            and distinguishes them only by argument types, so the member name
            is simply not in the string.  Measured on `vcl50.bpl` against the
            shipped Delphi 5 library: of 195 constructor exports the library
            also names, 175 are `Create` -- 89.7%, far below the standard the
            rest of this library holds to.  A destructor is the opposite case
            and is kept: all 122 the library also names are `Destroy`, which
            is what Delphi's single-destructor convention predicts.

        a unit the package does not contain
            the name cannot be placed, and an unplaced name is not RTL.
        """
        decoded = self.demangle(mangled)
        if decoded is None or decoded.kind not in ("function", "dtor"):
            return None
        components = list(decoded.components)
        if decoded.kind == "dtor":
            components[-1] = "Destroy"
        unit, rest = self.unit_of(components)
        if unit is None or not rest:
            return None
        rest = ["@" + c[len(_LINKPROC):] if c.startswith(_LINKPROC) else c
                for c in rest]
        rest = [strip_arguments(c) for c in rest]
        if not all(rest):
            return None
        return "::".join([unit] + rest)


Reading = collections.namedtuple("Reading", "name mangled")


def readings(path):
    """`{address: Reading}` for every export of `path` this pipeline will name.

    An address claimed by two different names is dropped rather than resolved.
    The linker folds identical bodies -- two empty finalisation routines, two
    generic instantiations that compile to the same code -- and a folded body
    is evidence against both names rather than for either, which is the rule
    `rttikb.py` already applies to a binary's own metadata.

    The mangled string is kept alongside the name because it carries the
    argument list and the calling convention, which is where this pipeline's
    prototypes come from.
    """
    package = Package(path)
    namer = Namer(package)
    claims = {}
    for mangled, address in package.exports():
        name = namer.name(mangled)
        if name is not None:
            claims.setdefault(address, {})[name] = mangled
    return {a: Reading(*next(iter(n.items())))
            for a, n in claims.items() if len(n) == 1}
