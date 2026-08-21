"""Stage knowledge-base procedures into a synthetic image Binary Ninja can analyse.

A KB procedure is a standalone code dump with no address; its cross-references
survive only as named fixups.  Leaving those operands at zero is not a cosmetic
loss: Binary Ninja's value analysis and no-return detection read through them,
and WARP hashes what analysis produces rather than raw bytes.  Measured on a
six-module pilot against a real Delphi 7 binary, relinking the fixups is worth
3.5x the match rate -- 1178 matches relinked versus 337 with zeroed operands.

Nothing is filtered out here.  Short thunks make poor signatures, but dropping
them at staging time would keep them out of the saved database too, and the
inclusion decision is much cheaper to revisit at generation time.
"""

import struct

BASE     = 0x400000
CODE_ORG = 0x401000
DATA_ORG = 0xA00000      # above the ~5.3 MB of staged RTL code
SPAN     = 0xC00000      # upper bound; render() trims to what is actually used
ALIGN    = 16


def is_thunk(code):
    """IDR's own rule for dumps that carry no distinguishing content."""
    return (len(code) < 8
            or (len(code) == 5 and code[0] == 0xE9)
            or (len(code) == 6 and code[0] == 0xE8 and code[5] == 0xC3))


class Layout(object):
    def __init__(self, kb, modules=None):
        self.kb = kb
        self.mods = {}
        self.files = {}
        for i in range(kb.sections['modules'][0]):
            m = kb.module(i)
            self.mods[m['id']] = m['name']
            self.files[m['id']] = m['filename']
        self.wanted = None
        if modules is not None:
            low = {m.lower() for m in modules}
            self.wanted = {mid for mid, nm in self.mods.items()
                           if nm.lower() in low}
        self.procs = []          # (addr, proc)
        self.by_name = {}
        self.data = {}
        self._build()

    def _build(self):
        cur = CODE_ORG
        for i in range(self.kb.sections['procs'][0]):
            off, _, _, _ = self.kb.ent('procs', i)
            mid = struct.unpack_from('<H', self.kb.m, off)[0]
            if self.wanted is not None and mid not in self.wanted:
                continue
            p = self.kb.proc(i)
            if p['dump_type'] != 'C' or not p['code']:
                continue
            self.procs.append((cur, p))
            mod = self.mods.get(mid, '')
            self.by_name.setdefault(p['name'], []).append(cur)
            self.by_name.setdefault(('%s.%s' % (mod, p['name'])).lower(),
                                    []).append(cur)
            cur += (len(p['code']) + ALIGN - 1) & ~(ALIGN - 1)
        self.code_end = cur

    def resolve(self, name, module_id):
        """Prefer a target in the referring module, then any unique match."""
        mod = self.mods.get(module_id, '')
        hit = self.by_name.get(('%s.%s' % (mod, name)).lower())
        if hit:
            return hit[0]
        hit = self.by_name.get(name)
        return hit[0] if hit else None

    def data_slot(self, name):
        if name not in self.data:
            self.data[name] = DATA_ORG + 4 * len(self.data)
        return self.data[name]

    def render(self, path):
        """Write the image, sized to its contents.

        The mapped extent is not cosmetic.  WARP masks a constant as a
        relocatable address when it lands inside (or within 0x10000 of) a
        mapped segment, so a needlessly large image masks immediates that a
        real binary would leave alone -- `and ecx, 0xffffff` is a field-offset
        mask in a 0.4 MB executable and an "address" in a 16 MB one, and the
        two hash differently.  Trim to the smallest span that holds the code
        and the data slots.
        """
        if self.code_end > DATA_ORG:
            raise ValueError("code overflows the data origin")
        buf = bytearray(SPAN)
        relinked = unresolved = 0
        for addr, p in self.procs:
            o = addr - BASE
            buf[o:o + len(p['code'])] = p['code']
            for ftype, fofs, fname in p['fixups']:
                if fofs + 4 > len(p['code']):
                    continue
                site = addr + fofs
                tgt = None
                if ftype == 'J':
                    tgt = self.resolve(fname, p['module_id'])
                    val = (tgt - (site + 4)) & 0xFFFFFFFF if tgt else 0
                else:
                    tgt = (self.resolve(fname, p['module_id']) if ftype == 'A'
                           else None) or self.data_slot(fname)
                    val = tgt
                relinked += 1 if tgt else 0
                unresolved += 0 if tgt else 1
                struct.pack_into('<I', buf, o + fofs, val)
        end = max(self.code_end, DATA_ORG + 4 * len(self.data) + 0x10) - BASE
        open(path, 'wb').write(bytes(buf[:end]))
        return relinked, unresolved
