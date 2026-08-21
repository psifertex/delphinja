#!/usr/bin/env python3
"""Throwaway parser for IDR knowledge base files (kbN.bin / syskbN.bin)."""
import struct, sys, mmap

U16 = struct.Struct('<H')
I32 = struct.Struct('<i')
U32 = struct.Struct('<I')

HDR = struct.Struct('<24s?iI256sidd')  # sig, isMSIL, fver, crc, desc, kbver, createDT, modifyDT
assert HDR.size == 24+1+4+4+256+4+8+8 - 0, HDR.size


class KB:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        m = self.m
        self.sig = bytes(m[0:24]).split(b'\0')[0].decode('latin-1')
        self.isMSIL = m[24]
        self.fver = I32.unpack_from(m, 25)[0]
        self.crc = U32.unpack_from(m, 29)[0]
        self.desc = bytes(m[33:33+256]).split(b'\0')[0].decode('latin-1')
        self.kbver = I32.unpack_from(m, 289)[0]
        self.createDT, self.modifyDT = struct.unpack_from('<dd', m, 293)
        self.data_start = 309
        # trailer
        self.sections_offset = U32.unpack_from(m, len(m) - 4)[0]
        o = self.sections_offset
        self.sections = {}
        for name in ('modules', 'consts', 'types', 'vars', 'resstrs', 'procs'):
            count = I32.unpack_from(m, o)[0]; o += 4
            maxsize = I32.unpack_from(m, o)[0]; o += 4
            tbl_off = o
            o += 16 * count
            self.sections[name] = (count, maxsize, tbl_off)
        self.sections_end = o

    def ent(self, section, idx):
        """Return (Offset, Size, ModId, NamId) of entry idx."""
        count, _, tbl = self.sections[section]
        if not 0 <= idx < count:
            raise IndexError(idx)
        return struct.unpack_from('<IIii', self.m, tbl + 16 * idx)

    def rec(self, section, idx):
        off, size, _, _ = self.ent(section, idx)
        return off, size

    # --- primitives -------------------------------------------------
    def pstr(self, p):
        """WORD len; len bytes; NUL. Returns (str, next_offset)."""
        n = U16.unpack_from(self.m, p)[0]
        s = bytes(self.m[p+2:p+2+n]).decode('latin-1')
        return s, p + 2 + n + 1

    # --- records ----------------------------------------------------
    def module(self, idx):
        p, _ = self.rec('modules', idx)
        mid = U16.unpack_from(self.m, p)[0]; p += 2
        name, p = self.pstr(p)
        fname, p = self.pstr(p)
        uses_num = U16.unpack_from(self.m, p)[0]; p += 2
        ids = list(struct.unpack_from('<%dH' % uses_num, self.m, p)); p += 2*uses_num
        names = []
        for _ in range(uses_num):
            s, p = self.pstr(p)
            names.append(s)
        return dict(idx=idx, id=mid, name=name, filename=fname,
                    uses=list(zip(ids, names)), end=p)

    def proc(self, idx, want_fixups=True):
        p0, size = self.rec('procs', idx)
        m = self.m
        p = p0
        mid = U16.unpack_from(m, p)[0]; p += 2
        name, p = self.pstr(p)
        embedded = m[p]; p += 1
        dumptype = chr(m[p]); p += 1
        methodkind = chr(m[p]); p += 1
        callkind = m[p]; p += 1
        vproc = I32.unpack_from(m, p)[0]; p += 4
        typedef, p = self.pstr(p)
        dump_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        dump_sz = U32.unpack_from(m, p)[0]; p += 4
        fixup_num = U32.unpack_from(m, p)[0]; p += 4
        code = bytes(m[p:p+dump_sz])
        relocs = bytes(m[p+dump_sz:p+2*dump_sz])
        fixups = []
        if want_fixups and dump_sz:
            q = p + 2*dump_sz
            for _ in range(fixup_num):
                ftype = chr(m[q]); q += 1
                fofs = U32.unpack_from(m, q)[0]; q += 4
                fname, q = self.pstr(q)
                fixups.append((ftype, fofs, fname))
        p = p1 + dump_total
        args_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        args_num = U16.unpack_from(m, p)[0]; p += 2
        args = []
        for _ in range(args_num):
            tag = m[p]; p += 1
            locflags = I32.unpack_from(m, p)[0]; p += 4
            ndx = I32.unpack_from(m, p)[0]; p += 4
            aname, p = self.pstr(p)
            atype, p = self.pstr(p)
            args.append(dict(tag=tag, locflags=locflags, ndx=ndx, name=aname, type=atype))
        p = p1 + args_total
        return dict(idx=idx, module_id=mid, name=name, embedded=bool(embedded),
                    dump_type=dumptype, method_kind=methodkind, call_kind=callkind,
                    vproc=vproc, typedef=typedef, dump_sz=dump_sz, fixup_num=fixup_num,
                    code=code, relocs=relocs, fixups=fixups, args=args,
                    rec_off=p0, rec_size=size, consumed=p - p0)

    def var(self, idx):
        p, _ = self.rec('vars', idx)
        mid = U16.unpack_from(self.m, p)[0]; p += 2
        name, p = self.pstr(p)
        vt = chr(self.m[p]); p += 1
        typedef, p = self.pstr(p)
        absname, p = self.pstr(p)
        return dict(module_id=mid, name=name, type=vt, typedef=typedef, absname=absname, end=p)

    def resstr(self, idx):
        p, _ = self.rec('resstrs', idx)
        mid = U16.unpack_from(self.m, p)[0]; p += 2
        name, p = self.pstr(p)
        typedef, p = self.pstr(p)
        ctx, p = self.pstr(p)
        return dict(module_id=mid, name=name, typedef=typedef, context=ctx, end=p)

    def const(self, idx):
        p, _ = self.rec('consts', idx)
        m = self.m
        mid = U16.unpack_from(m, p)[0]; p += 2
        name, p = self.pstr(p)
        ct = chr(m[p]); p += 1
        typedef, p = self.pstr(p)
        value, p = self.pstr(p)
        dump_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        dump_sz = U32.unpack_from(m, p)[0]; p += 4
        fixup_num = U32.unpack_from(m, p)[0]; p += 4
        dump = bytes(m[p:p+dump_sz])
        relocs = bytes(m[p+dump_sz:p+2*dump_sz])
        fixups = []
        if dump_sz:
            q = p + 2*dump_sz
            for _ in range(fixup_num):
                ft = chr(m[q]); q += 1
                fo = U32.unpack_from(m, q)[0]; q += 4
                fn, q = self.pstr(q)
                fixups.append((ft, fo, fn))
        p = p1 + dump_total
        return dict(module_id=mid, name=name, type=ct, typedef=typedef, value=value,
                    dump_sz=dump_sz, dump=dump, relocs=relocs, fixups=fixups, end=p)

    def type_(self, idx):
        p, _ = self.rec('types', idx)
        m = self.m
        size = U32.unpack_from(m, p)[0]; p += 4
        mid = U16.unpack_from(m, p)[0]; p += 2
        name, p = self.pstr(p)
        kind = m[p]; p += 1
        vmcnt = U16.unpack_from(m, p)[0]; p += 2
        decl, p = self.pstr(p)
        dump_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        dump_sz = U32.unpack_from(m, p)[0]; p += 4
        fixup_num = U32.unpack_from(m, p)[0]; p += 4
        dump = bytes(m[p:p+dump_sz])
        relocs = bytes(m[p+dump_sz:p+2*dump_sz])
        p = p1 + dump_total
        fields_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        fields_num = U16.unpack_from(m, p)[0]; p += 2
        fields = []
        for _ in range(fields_num):
            scope = m[p]; p += 1
            ofs = I32.unpack_from(m, p)[0]; p += 4
            case = I32.unpack_from(m, p)[0]; p += 4
            fname, p = self.pstr(p)
            ftype, p = self.pstr(p)
            fields.append(dict(scope=scope, offset=ofs, case=case, name=fname, type=ftype))
        p = p1 + fields_total
        props_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        props_num = U16.unpack_from(m, p)[0]; p += 2
        props = []
        for _ in range(props_num):
            scope = m[p]; p += 1
            index = I32.unpack_from(m, p)[0]; p += 4
            dispid = I32.unpack_from(m, p)[0]; p += 4
            pname, p = self.pstr(p)
            ptype, p = self.pstr(p)
            rd, p = self.pstr(p)
            wr, p = self.pstr(p)
            st, p = self.pstr(p)
            props.append(dict(scope=scope, index=index, dispid=dispid, name=pname,
                              type=ptype, read=rd, write=wr, stored=st))
        assert p == p1 + props_total, (p, p1 + props_total)
        p = p1 + props_total
        methods_total = U32.unpack_from(m, p)[0]; p += 4
        p1 = p
        methods_num = U16.unpack_from(m, p)[0]; p += 2
        methods = []
        for _ in range(methods_num):
            scope = m[p]; p += 1
            mk = chr(m[p]); p += 1
            proto, p = self.pstr(p)
            methods.append(dict(scope=scope, kind=mk, proto=proto))
        p = p1 + methods_total
        return dict(module_id=mid, name=name, kind=kind, kindc=chr(kind), size=size,
                    vmcnt=vmcnt, decl=decl, dump_sz=dump_sz, dump=dump, relocs=relocs,
                    fields=fields, props=props, methods=methods, end=p)


if __name__ == '__main__':
    kb = KB(sys.argv[1] if len(sys.argv) > 1 else 'kb7/kb7.bin')
    print('sig=%r isMSIL=%d fver=%d crc=%#x kbver=%d desc=%r createDT=%r modifyDT=%r'
          % (kb.sig, kb.isMSIL, kb.fver, kb.crc, kb.kbver, kb.desc, kb.createDT, kb.modifyDT))
    print('file size          :', len(kb.m))
    print('SectionsOffset     :', kb.sections_offset)
    print('sections end       :', kb.sections_end, '(file size - 4 =', len(kb.m)-4, ')')
    for n, (c, mx, t) in kb.sections.items():
        print('  %-8s count=%-8d maxdatasize=%-8d tbl@%d' % (n, c, mx, t))
