"""COFF object reader -- the FPC equivalent of `kb.py`.

The Delphi side of this project gets name, code bytes and a relocation mask per
procedure out of an IDR knowledge base.  Free Pascal hands over the same triple
for free, and better: on Windows the compiler sets `tf_smartlink_sections`
unconditionally (`compiler/systems/i_win.pas`), and `thlcgobj.gen_proc_symbol`
opens a fresh section for *every* procdef, so a shipped `.o` carries one
`.text.n_<lowercased mangled name>` section per function, with the exact bytes
the linker will copy and the *authoritative* relocation table rather than a
reconstructed mask.

So this module replaces `kb.py`, and nothing here is FPC-specific: it is a
plain PE/COFF relocatable-object reader.  It deliberately does not try to be a
linker -- it exposes sections, symbols and relocations, and `fpcstage.py`
decides where things land.

Format reference: PE/COFF specification, sections 3 (section table),
4 (COFF relocations) and 5 (symbol table).
"""

import struct

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664

# Section characteristics.
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_LNK_REMOVE = 0x00000800
SCN_LNK_NRELOC_OVFL = 0x01000000
SCN_MEM_DISCARDABLE = 0x02000000
SCN_ALIGN_MASK = 0x00F00000

# Storage classes.
SYM_CLASS_EXTERNAL = 2
SYM_CLASS_STATIC = 3
SYM_CLASS_LABEL = 6
SYM_CLASS_FILE = 103
SYM_CLASS_SECTION = 104

# Symbol complex type: (type >> 4) == 2 means "function".
SYM_DTYPE_FUNCTION = 2

# Relocation types that actually occur in FPC-generated objects.
REL_I386_DIR32 = 0x0006
REL_I386_DIR32NB = 0x0007
REL_I386_SECTION = 0x000A
REL_I386_SECREL = 0x000B
REL_I386_REL32 = 0x0014

REL_AMD64_ADDR64 = 0x0001
REL_AMD64_ADDR32 = 0x0002
REL_AMD64_ADDR32NB = 0x0003
REL_AMD64_REL32 = 0x0004
REL_AMD64_REL32_1 = 0x0005
REL_AMD64_REL32_5 = 0x0009
REL_AMD64_SECTION = 0x000A
REL_AMD64_SECREL = 0x000B


class Symbol(object):
    __slots__ = ("name", "value", "section", "type", "storage")

    def __init__(self, name, value, section, type_, storage):
        self.name = name
        self.value = value
        self.section = section          # 1-based; 0 = undefined, -1/-2 special
        self.type = type_
        self.storage = storage

    @property
    def is_function(self):
        return (self.type >> 4) == SYM_DTYPE_FUNCTION

    @property
    def is_defined(self):
        return self.section > 0

    @property
    def is_undefined(self):
        return self.section == 0 and self.value == 0

    @property
    def is_common(self):
        """Uninitialised shared datum; `value` is its size, not an offset."""
        return self.section == 0 and self.value > 0

    @property
    def is_global(self):
        return self.storage == SYM_CLASS_EXTERNAL

    def __repr__(self):
        return "<Symbol %s sec=%d val=%#x>" % (self.name, self.section, self.value)


class Section(object):
    __slots__ = ("name", "index", "flags", "size", "data", "relocs", "align")

    def __init__(self, name, index, flags, size, data, relocs, align):
        self.name = name
        self.index = index              # 1-based, matching Symbol.section
        self.flags = flags
        self.size = size
        self.data = data                # b"" for .bss
        self.relocs = relocs            # [(offset, symbol_index, type)]
        self.align = align

    @property
    def is_code(self):
        return bool(self.flags & SCN_CNT_CODE)

    @property
    def is_bss(self):
        return bool(self.flags & SCN_CNT_UNINITIALIZED_DATA)

    @property
    def is_allocated(self):
        """Does this section occupy space in a linked image?

        `.debug_frame` and friends are marked discardable and never make it
        into the image, so placing them would only inflate the staged extent
        -- which matters, because WARP masks constants that fall inside it.
        """
        if self.flags & (SCN_LNK_REMOVE | SCN_MEM_DISCARDABLE):
            return False
        return bool(self.flags & (SCN_CNT_CODE | SCN_CNT_INITIALIZED_DATA
                                  | SCN_CNT_UNINITIALIZED_DATA))

    def __repr__(self):
        return "<Section %s size=%d relocs=%d>" % (
            self.name, self.size, len(self.relocs))


class ObjectFile(object):
    """One relocatable COFF object."""

    def __init__(self, data, path=""):
        self.path = path
        self.data = data
        if len(data) < 20:
            raise ValueError("%s: too short for a COFF header" % path)
        (self.machine, nsec, _stamp, symptr, nsym,
         optsize, self.characteristics) = struct.unpack_from("<HHIIIHH", data, 0)
        if self.machine not in (MACHINE_I386, MACHINE_AMD64):
            raise ValueError("%s: unsupported COFF machine %#x"
                             % (path, self.machine))
        self.bits = 64 if self.machine == MACHINE_AMD64 else 32
        self._read_strings(symptr, nsym)
        self.sections = self._read_sections(20 + optsize, nsec)
        self.symbols = self._read_symbols(symptr, nsym)

    # -- strings ---------------------------------------------------------

    def _read_strings(self, symptr, nsym):
        self._strings = b""
        if not symptr or not nsym:
            return
        off = symptr + 18 * nsym
        if off + 4 > len(self.data):
            return
        size = struct.unpack_from("<I", self.data, off)[0]
        # The size field counts itself; a table of exactly 4 bytes is empty.
        self._strings = self.data[off:off + max(size, 4)]

    def _string(self, offset):
        if offset >= len(self._strings):
            return ""
        end = self._strings.find(b"\0", offset)
        raw = self._strings[offset:] if end < 0 else self._strings[offset:end]
        return raw.decode("latin-1")

    def _name8(self, raw):
        """An 8-byte COFF name field, in any of its three spellings."""
        if raw[:4] == b"\0\0\0\0":
            return self._string(struct.unpack_from("<I", raw, 4)[0])
        if raw[0:1] == b"/":
            tail = raw[1:].rstrip(b"\0").decode("latin-1")
            if tail.startswith("/"):
                # GNU base64 form for offsets past 9,999,999.
                return self._string(_base64_offset(tail[1:]))
            if tail.isdigit():
                return self._string(int(tail))
        return raw.rstrip(b"\0").decode("latin-1")

    # -- sections --------------------------------------------------------

    def _read_sections(self, off, count):
        out = []
        for i in range(count):
            base = off + 40 * i
            if base + 40 > len(self.data):
                break
            raw = self.data[base:base + 8]
            (vsize, _vaddr, rawsize, rawptr, relptr,
             _lineptr, nrel, _nline, flags) = struct.unpack_from(
                "<IIIIIIHHI", self.data, base + 8)
            name = self._name8(raw)
            # An object file has no virtual addresses; the size that matters is
            # SizeOfRawData, except for .bss where the raw size is zero.
            size = rawsize if rawsize else vsize
            if flags & SCN_CNT_UNINITIALIZED_DATA:
                data = b""
                size = max(vsize, rawsize)
            else:
                data = self.data[rawptr:rawptr + rawsize] if rawptr else b""
            relocs = self._read_relocs(relptr, nrel, flags)
            align_bits = (flags & SCN_ALIGN_MASK) >> 20
            align = 1 << (align_bits - 1) if align_bits else 1
            out.append(Section(name, i + 1, flags, size, data, relocs, align))
        return out

    def _read_relocs(self, ptr, count, flags):
        if not ptr or not count:
            return []
        # More than 0xFFFF relocations: the real count lives in the first
        # (otherwise unused) entry, which is then skipped.
        if count == 0xFFFF and (flags & SCN_LNK_NRELOC_OVFL):
            count = struct.unpack_from("<I", self.data, ptr)[0] - 1
            ptr += 10
        out = []
        for i in range(count):
            base = ptr + 10 * i
            if base + 10 > len(self.data):
                break
            out.append(struct.unpack_from("<IIH", self.data, base))
        return out

    # -- symbols ---------------------------------------------------------

    def _read_symbols(self, ptr, count):
        """Every slot, aux records included.

        Relocations index this table by slot, so the aux entries have to keep
        their positions; they are returned as None.
        """
        out = []
        i = 0
        while i < count:
            base = ptr + 18 * i
            if base + 18 > len(self.data):
                break
            raw = self.data[base:base + 8]
            value, section, type_, storage, naux = struct.unpack_from(
                "<IhHBB", self.data, base + 8)
            out.append(Symbol(self._name8(raw), value, section, type_, storage))
            out.extend([None] * naux)
            i += 1 + naux
        return out


def _base64_offset(text):
    """GNU's base64 spelling of a long-name offset (`//` section names)."""
    alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz0123456789+/")
    value = 0
    for ch in text:
        value = value * 64 + alphabet.index(ch)
    return value


def load(path):
    with open(path, "rb") as fh:
        return ObjectFile(fh.read(), path)
