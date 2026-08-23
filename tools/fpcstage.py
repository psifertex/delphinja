"""Lay shipped FPC object files out into one image and link it.

This is `stage.py`'s job with better input.  The Delphi side has to reconstruct
cross-references from *named* fixups, guessing which module a name refers to;
an FPC object carries a real relocation table indexed by real symbol table
slots, so nothing has to be guessed -- the same "lay it out, then make the
operands point somewhere true" idea, doing less work.

Why bother linking at all: Binary Ninja's value analysis and no-return
detection read through call operands, and WARP hashes what analysis produces
rather than raw bytes.  On the Delphi side relinking was worth 3.5x the match
rate, and there is no reason for FPC to be different.

Layout is code first, then initialised data, then `.bss`, then one slot per
undefined symbol.  Undefined symbols are Win32 imports and anything from an
object outside the build set; they get an address inside the image so that
WARP masks the operand as relocatable, exactly as it would in a real binary.
"""

import os
import struct

from . import coff

BASE = 0x400000
CODE_ORG = 0x401000
CODE_ALIGN = 16
SECTION_GAP = 0x1000          # between the code, data, bss and import areas

REL_ABS, REL_PCREL = 0, 1

# (size in bytes, kind) per relocation type, per machine.
_I386 = {
    coff.REL_I386_DIR32: (4, REL_ABS),
    coff.REL_I386_DIR32NB: (4, REL_ABS),
    coff.REL_I386_REL32: (4, REL_PCREL),
}
_AMD64 = {
    coff.REL_AMD64_ADDR64: (8, REL_ABS),
    coff.REL_AMD64_ADDR32: (4, REL_ABS),
    coff.REL_AMD64_ADDR32NB: (4, REL_ABS),
    coff.REL_AMD64_REL32: (4, REL_PCREL),
    coff.REL_AMD64_REL32_1: (4, REL_PCREL),
    0x0006: (4, REL_PCREL),
    0x0007: (4, REL_PCREL),
    0x0008: (4, REL_PCREL),
    coff.REL_AMD64_REL32_5: (4, REL_PCREL),
}
# REL32_1..REL32_5 mean "relative to the address `n` bytes past the field".
_REL32_BIAS = {coff.REL_AMD64_REL32_1: 1, 0x0006: 2, 0x0007: 3, 0x0008: 4,
               coff.REL_AMD64_REL32_5: 5}


def is_thunk(code):
    """Dumps with no distinguishing content, by IDR's rule (see stage.py).

    Kept identical to the Delphi side on purpose: a five-byte jump is exactly
    as useless as a signature whichever compiler emitted it.
    """
    return (len(code) < 8
            or (len(code) == 5 and code[0] == 0xE9)
            or (len(code) == 6 and code[0] == 0xE8 and code[5] == 0xC3))


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


class Layout(object):
    """Every object in the build set, placed and linked."""

    def __init__(self, paths, log=print):
        self.log = log
        self.objects = []
        self.units = []                  # unit name per object, by index
        self.bits = 32
        for path in paths:
            try:
                obj = coff.load(path)
            except Exception as exc:                     # noqa: BLE001
                log("skipped %s: %s" % (os.path.basename(path), exc))
                continue
            self.objects.append(obj)
            self.units.append(os.path.splitext(os.path.basename(path))[0])
            self.bits = obj.bits
        self.ptr = self.bits // 8

        self.secaddr = {}                # (obj, section index) -> address
        self.globals = {}                # mangled name -> address
        self.slots = {}                  # undefined name -> address
        self.procs = []                  # (address, record)
        self._place()

    # -- placement -------------------------------------------------------

    def _place(self):
        cur = CODE_ORG
        seen = set()
        for oi, obj in enumerate(self.objects):
            for sec in obj.sections:
                if not sec.is_code or not sec.size or not sec.is_allocated:
                    continue
                key = self._section_key(oi, sec)
                # The same routine is emitted into several objects when it is
                # inlined or instantiated more than once. Staging both copies
                # would put two identical bodies under two names into the
                # library, which is an ambiguity decline at match time.
                if key is not None and key in seen:
                    continue
                if key is not None:
                    seen.add(key)
                cur = _align(cur, max(sec.align, CODE_ALIGN))
                self.secaddr[(oi, sec.index)] = cur
                cur += sec.size
        self.code_end = cur

        cur = _align(cur + SECTION_GAP, 0x1000)
        self.data_org = cur
        for oi, obj in enumerate(self.objects):
            for sec in obj.sections:
                if (sec.is_code or sec.is_bss or not sec.size
                        or not sec.is_allocated):
                    continue
                key = self._section_key(oi, sec)
                if key is not None and key in seen:
                    continue
                if key is not None:
                    seen.add(key)
                cur = _align(cur, max(sec.align, 4))
                self.secaddr[(oi, sec.index)] = cur
                cur += sec.size
        self.data_end = cur

        cur = _align(cur + SECTION_GAP, 0x1000)
        self.bss_org = cur
        for oi, obj in enumerate(self.objects):
            for sec in obj.sections:
                if not sec.is_bss or not sec.size or not sec.is_allocated:
                    continue
                key = self._section_key(oi, sec)
                if key is not None and key in seen:
                    continue
                if key is not None:
                    seen.add(key)
                cur = _align(cur, max(sec.align, 4))
                self.secaddr[(oi, sec.index)] = cur
                cur += sec.size
        self.bss_end = cur
        self.slot_org = _align(cur + SECTION_GAP, 0x1000)

        self._index_symbols()
        self._index_procs()

    def _section_key(self, oi, sec):
        """The identity a duplicate section would share: the global symbol
        defined at its start.  `None` means "no global here, keep it"."""
        obj = self.objects[oi]
        for sym in obj.symbols:
            if (sym is not None and sym.is_global and sym.section == sec.index
                    and sym.value == 0):
                return sym.name
        return None

    def _index_symbols(self):
        for oi, obj in enumerate(self.objects):
            for sym in obj.symbols:
                if sym is None or not sym.is_global or not sym.is_defined:
                    continue
                addr = self.secaddr.get((oi, sym.section))
                if addr is None:
                    continue
                self.globals.setdefault(sym.name, addr + sym.value)

    def _index_procs(self):
        """Every function body that was placed, with its extent.

        A `.text.n_*` section holds exactly one routine -- `thlcgobj` opens a
        section per procdef -- but a plain `.text` can hold several, so
        extents come from the symbols rather than from the section.
        """
        for oi, obj in enumerate(self.objects):
            unit = self.units[oi]
            for sec in obj.sections:
                base = self.secaddr.get((oi, sec.index))
                if base is None or not sec.is_code:
                    continue
                # An assembler routine can carry two names for one body
                # (`FPC_MOVE` and `fpc_move`); keep the exported spelling, so
                # the library does not offer two names for the same bytes.
                best = {}
                for s in obj.symbols:
                    if (s is None or s.section != sec.index
                            or s.value >= sec.size or s.name.startswith(".")
                            or s.storage not in (coff.SYM_CLASS_EXTERNAL,
                                                 coff.SYM_CLASS_STATIC)):
                        continue
                    rank = (s.is_global, s.name.isupper(), s.name)
                    if s.value not in best or rank > best[s.value][0]:
                        best[s.value] = (rank, s.name)
                marks = sorted((off, nm) for off, (_, nm) in best.items())
                if not marks:
                    # Nothing named it, but the section name still carries the
                    # (lowercased) mangled name.
                    if not sec.name.startswith(".text.n_"):
                        continue
                    marks = [(0, sec.name[len(".text.n_"):])]
                width = 8 if self.bits == 64 else 4
                for i, (offset, name) in enumerate(marks):
                    end = marks[i + 1][0] if i + 1 < len(marks) else sec.size
                    if end <= offset:
                        continue
                    # The bytes the linker rewrites. Keeping them per routine
                    # is what lets a match be checked against the reference
                    # byte for byte instead of approximately.
                    holes = set()
                    for roff, _sym, _type in sec.relocs:
                        if offset <= roff < end:
                            holes.update(range(roff - offset,
                                               min(roff - offset + width,
                                                   end - offset)))
                    self.procs.append((base + offset, {
                        "name": name,
                        "unit": unit,
                        "size": end - offset,
                        "code": sec.data[offset:end],
                        "holes": holes,
                        "object": oi,
                    }))

    # -- linking ---------------------------------------------------------

    def _slot(self, name):
        if name not in self.slots:
            self.slots[name] = self.slot_org + self.ptr * len(self.slots)
        return self.slots[name]

    def _target(self, oi, index):
        obj = self.objects[oi]
        if index >= len(obj.symbols):
            return None
        sym = obj.symbols[index]
        if sym is None:
            return None
        if sym.is_defined:
            addr = self.secaddr.get((oi, sym.section))
            if addr is not None:
                return addr + sym.value
            # The section was dropped as a duplicate; the surviving copy is
            # under the same global name.
        return self.globals.get(sym.name) or self._slot(sym.name)

    def render(self, path):
        buf = bytearray()
        applied = skipped = 0

        def grow(size):
            if len(buf) < size:
                buf.extend(b"\0" * (size - len(buf)))

        for (oi, index), addr in self.secaddr.items():
            sec = self.objects[oi].sections[index - 1]
            if not sec.data:
                continue
            off = addr - BASE
            grow(off + len(sec.data))
            buf[off:off + len(sec.data)] = sec.data

        table = _AMD64 if self.bits == 64 else _I386
        for (oi, index), addr in self.secaddr.items():
            sec = self.objects[oi].sections[index - 1]
            for offset, sym_index, rtype in sec.relocs:
                if rtype == 0:                  # IMAGE_REL_*_ABSOLUTE: a
                    continue                    # placeholder, not a fixup
                shape = table.get(rtype)
                if shape is None or offset + shape[0] > sec.size:
                    skipped += 1
                    continue
                size, kind = shape
                target = self._target(oi, sym_index)
                if target is None:
                    skipped += 1
                    continue
                pos = addr - BASE + offset
                if pos + size > len(buf):
                    skipped += 1
                    continue
                addend = int.from_bytes(buf[pos:pos + size], "little",
                                        signed=True)
                if kind == REL_PCREL:
                    site = addr + offset + size + _REL32_BIAS.get(rtype, 0)
                    value = target + addend - site
                else:
                    value = target + addend
                buf[pos:pos + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(
                    size, "little")
                applied += 1

        # The import slots are the highest thing in the image; leave them
        # mapped so WARP masks references to them as addresses.
        end = self.slot_org - BASE + self.ptr * (len(self.slots) + 4)
        grow(end)
        with open(path, "wb") as fh:
            fh.write(bytes(buf[:end]))
        return applied, skipped

    def summary(self):
        return ("%d objects, %d functions, %d KB code, %d KB data, "
                "%d import slots"
                % (len(self.objects), len(self.procs),
                   (self.code_end - CODE_ORG) // 1024,
                   (self.bss_end - self.data_org) // 1024, len(self.slots)))
