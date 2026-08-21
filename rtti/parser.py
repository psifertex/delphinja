"""Pure parser for Delphi (2..2007/x86, non-Unicode) RTTI, VMT and metadata tables.

Nothing in here imports Binary Ninja.  The whole parser talks to the binary
through a `Reader`, so the same code runs headless against a raw PE or inside
the plugin against a BinaryView.
"""

import struct

# ---------------------------------------------------------------- primitives

TYPE_KINDS = {
    0: "tkUnknown", 1: "tkInteger", 2: "tkChar", 3: "tkEnumeration",
    4: "tkFloat", 5: "tkString", 6: "tkSet", 7: "tkClass", 8: "tkMethod",
    9: "tkWChar", 10: "tkLString", 11: "tkWString", 12: "tkVariant",
    13: "tkArray", 14: "tkRecord", 15: "tkInterface", 16: "tkInt64",
    17: "tkDynArray",
}

ORD_TYPES = {0: "otSByte", 1: "otUByte", 2: "otSWord", 3: "otUWord",
             4: "otSLong", 5: "otULong"}
FLOAT_TYPES = {0: "ftSingle", 1: "ftDouble", 2: "ftExtended", 3: "ftComp",
               4: "ftCurr"}
METHOD_KINDS = {0: "mkProcedure", 1: "mkFunction", 2: "mkConstructor",
                3: "mkDestructor", 4: "mkClassProcedure", 5: "mkClassFunction",
                6: "mkClassConstructor", 7: "mkClassDestructor",
                8: "mkOperatorOverload"}
PARAM_FLAGS = [(0x01, "pfVar"), (0x02, "pfConst"), (0x04, "pfArray"),
               (0x08, "pfAddress"), (0x10, "pfReference"), (0x20, "pfOut")]

# VMT slots at negative offsets from the VMT (class pointer) address.
VMT_NEG = [
    (-76, "vmtSelfPtr"), (-72, "vmtIntfTable"), (-68, "vmtAutoTable"),
    (-64, "vmtInitTable"), (-60, "vmtTypeInfo"), (-56, "vmtFieldTable"),
    (-52, "vmtMethodTable"), (-48, "vmtDynamicTable"), (-44, "vmtClassName"),
    (-40, "vmtInstanceSize"), (-36, "vmtParent"),
]
# Virtual slots that every TObject descendant carries, in order from -32.
VMT_STD_METHODS = [
    (-32, "SafeCallException"), (-28, "AfterConstruction"),
    (-24, "BeforeDestruction"), (-20, "Dispatch"), (-16, "DefaultHandler"),
    (-12, "NewInstance"), (-8, "FreeInstance"), (-4, "Destroy"),
]
VMT_HEADER_SIZE = 76        # Delphi 3 - 2007; see Layout for the others


class Layout(object):
    """The dimensions of one Delphi RTTI dialect.

    Only the numbers change between versions, never the shape of the tables,
    so a descriptor threaded through the reader covers every era without
    duplicating any parsing logic.

    Every era keeps the same eleven data slots; what moved is the number of
    standard TObject virtual slots that follow them, because TObject itself
    gained virtual methods. Delphi 2 had five, Delphi 3 through 2007 have
    eight, and 2009 onwards have eleven -- which is why a parser hardcoded to
    a 76-byte header sees nothing at all in a modern binary, 32-bit included.
    """

    #: standard TObject virtual slots by era
    VIRTUAL_COUNTS = (5, 8, 11, 14)
    DATA_SLOTS = 11

    def __init__(self, ptr_size=4, n_virtuals=8):
        self.ptr_size = ptr_size
        self.n_virtuals = n_virtuals
        self.header_size = (self.DATA_SLOTS + n_virtuals) * ptr_size

    def __repr__(self):
        return "<Layout ptr=%d virtuals=%d header=%d>" % (
            self.ptr_size, self.n_virtuals, self.header_size)

    @property
    def class_name_offset(self):
        """vmtClassName sits eight pointer slots past vmtSelfPtr in every era."""
        return 8 * self.ptr_size


DEFAULT_LAYOUT = Layout()


def detect_layout(reader, ranges, window=0x40000, ptr_sizes=(4, 8)):
    """Work out which dialect a binary uses by asking it.

    Fingerprinting the compiler from strings is unreliable -- most binaries
    carry no version marker at all -- and a version-to-layout table would be
    wrong regardless, because the same Delphi version emits different headers
    depending on whether the C++ ABI slots are reserved. So probe instead:
    for each candidate header size, count the addresses that both self-
    reference at that distance and have a plausible class name where the
    layout says one should be. The correct size wins by a wide margin.
    """
    best, best_score = None, 0
    for ptr_size in ptr_sizes:
        read = reader.u32 if ptr_size == 4 else reader.u64
        for n_virtuals in Layout.VIRTUAL_COUNTS:
            layout = Layout(ptr_size, n_virtuals)
            score = 0
            for start, end in ranges:
                limit = min(end, start + window)
                for addr in range(start, limit, ptr_size):
                    if read(addr) != addr + layout.header_size:
                        continue
                    name_ptr = read(addr + layout.class_name_offset)
                    if name_ptr is None or not reader.is_mapped(name_ptr):
                        continue
                    name, _ = reader.shortstr(name_ptr)
                    if is_identifier(name):
                        score += 1
            if score > best_score:
                best, best_score = layout, score
    return best, best_score


class Reader(object):
    """Byte access plus a notion of which addresses are actually mapped."""

    def __init__(self, read, is_mapped, is_code=None, ptr_size=4, layout=None):
        self._read = read
        self.is_mapped = is_mapped
        self.is_code = is_code or is_mapped
        self.ptr_size = ptr_size
        # Which RTTI dialect to read. Detection sets this; the default keeps
        # the Delphi 3 - 2007 behaviour for callers that never detect.
        self.layout = layout or DEFAULT_LAYOUT

    def ptr(self, addr):
        """Read one pointer at the layout's width."""
        return self.u32(addr) if self.layout.ptr_size == 4 else self.u64(addr)

    def bytes(self, addr, length):
        data = self._read(addr, length)
        return data if data else b""

    def u8(self, addr):
        d = self.bytes(addr, 1)
        return d[0] if len(d) == 1 else None

    def u16(self, addr):
        d = self.bytes(addr, 2)
        return struct.unpack("<H", d)[0] if len(d) == 2 else None

    def i16(self, addr):
        d = self.bytes(addr, 2)
        return struct.unpack("<h", d)[0] if len(d) == 2 else None

    def u32(self, addr):
        d = self.bytes(addr, 4)
        return struct.unpack("<I", d)[0] if len(d) == 4 else None

    def i32(self, addr):
        d = self.bytes(addr, 4)
        return struct.unpack("<i", d)[0] if len(d) == 4 else None

    def i64(self, addr):
        d = self.bytes(addr, 8)
        return struct.unpack("<q", d)[0] if len(d) == 8 else None

    def u64(self, addr):
        d = self.bytes(addr, 8)
        return struct.unpack("<Q", d)[0] if len(d) == 8 else None

    def shortstr(self, addr, max_len=255):
        """Delphi ShortString: length byte followed by that many chars.

        Returns (text, address_just_past_the_string) or (None, addr) when the
        bytes cannot be a plausible identifier.
        """
        n = self.u8(addr)
        if n is None or n > max_len:
            return None, addr
        raw = self.bytes(addr + 1, n)
        if len(raw) != n:
            return None, addr
        return raw.decode("latin-1"), addr + 1 + n


def is_identifier(text, min_len=1, max_len=128):
    if text is None or not (min_len <= len(text) <= max_len):
        return False
    # Delphi identifiers, plus '.' for qualified unit names, the compiler's
    # own decorations ('$', '@'), and the angle brackets and commas that
    # generic type names carry -- TArray<System.Byte> is a perfectly ordinary
    # RTTI name from 2010 onwards, and rejecting it discards a large share of
    # the type records in a modern binary.
    return all(c.isalnum() or c in "_.$@<>," for c in text)



def _unitname(r, p):
    """Read a trailing UnitName ShortString if one is really there.

    A few System-unit records (Boolean, Char, ...) are hand-written in the
    RTL's assembler and stop right after the name list, so the bytes that
    follow are padding rather than a unit name.
    """
    name, p2 = r.shortstr(p)
    if is_identifier(name):
        return name, p2
    return None, p


# ---------------------------------------------------------------- TTypeInfo

class TypeInfo(object):
    def __init__(self, addr):
        self.addr = addr            # address of the Kind byte
        self.ptr_addr = None        # address of the PPTypeInfo cell, if present
        self.kind = None
        self.kind_name = None
        self.name = None
        self.unit = None
        self.end = addr             # one past the last byte of the record
        self.data = {}              # kind-specific decoded fields
        self.props = []             # published properties, tkClass only
        self.fields = []            # for tkRecord init tables

    def __repr__(self):
        return "<TypeInfo %08x %s %s>" % (self.addr, self.kind_name, self.name)


def parse_typeinfo(r, addr, follow_props=True):
    """Parse a TTypeInfo record at `addr` (the Kind byte). None if implausible."""
    kind = r.u8(addr)
    if kind is None or kind not in TYPE_KINDS or kind == 0:
        return None
    name, p = r.shortstr(addr + 1)
    if not is_identifier(name):
        return None

    ti = TypeInfo(addr)
    ti.kind = kind
    ti.kind_name = TYPE_KINDS[kind]
    ti.name = name

    if kind in (1, 2, 9):                                    # ordinal types
        ti.data["OrdType"] = ORD_TYPES.get(r.u8(p), r.u8(p))
        ti.data["MinValue"] = r.i32(p + 1)
        ti.data["MaxValue"] = r.i32(p + 5)
        p += 9
    elif kind == 3:                                          # tkEnumeration
        ti.data["OrdType"] = ORD_TYPES.get(r.u8(p), r.u8(p))
        lo, hi = r.i32(p + 1), r.i32(p + 5)
        base = r.u32(p + 9)
        ti.data["MinValue"], ti.data["MaxValue"] = lo, hi
        ti.data["BaseType"] = base
        p += 13
        names = []
        if lo is not None and hi is not None and 0 <= hi - lo < 4096:
            for _ in range(hi - lo + 1):
                s, p = r.shortstr(p)
                if not is_identifier(s):
                    return None
                names.append(s)
        ti.data["Names"] = names
        ti.unit, p = _unitname(r, p)
    elif kind == 4:                                          # tkFloat
        ti.data["FloatType"] = FLOAT_TYPES.get(r.u8(p), r.u8(p))
        p += 1
    elif kind == 5:                                          # tkString (short)
        ti.data["MaxLength"] = r.u8(p)
        p += 1
    elif kind == 6:                                          # tkSet
        ti.data["OrdType"] = ORD_TYPES.get(r.u8(p), r.u8(p))
        ti.data["CompType"] = r.u32(p + 1)
        p += 5
    elif kind == 7:                                          # tkClass
        ti.data["ClassType"] = r.u32(p)
        ti.data["ParentInfo"] = r.u32(p + 4)
        ti.data["PropCount"] = r.i16(p + 8)
        p += 10
        ti.unit, p = _unitname(r, p)
        if follow_props:
            ti.props, p = _parse_props(r, p)
    elif kind == 8:                                          # tkMethod
        mk = r.u8(p)
        ti.data["MethodKind"] = METHOD_KINDS.get(mk, mk)
        n = r.u8(p + 1)
        ti.data["ParamCount"] = n
        p += 2
        params = []
        if n is not None and n <= 64:
            for _ in range(n):
                flags = r.u8(p)
                p += 1
                pname, p = r.shortstr(p)
                ptype, p = r.shortstr(p)
                params.append({
                    "Flags": [nm for bit, nm in PARAM_FLAGS if flags and flags & bit],
                    "Name": pname, "Type": ptype})
        ti.data["Params"] = params
        if mk in (1, 5):                                     # function result
            ti.data["ResultType"], p = r.shortstr(p)
    elif kind == 13:                                         # tkArray
        ti.data["Size"] = r.i32(p)
        ti.data["ElCount"] = r.i32(p + 4)
        ti.data["ElType"] = r.u32(p + 8)
        p += 12
    elif kind == 14:                                         # tkRecord
        ti.data["Size"] = r.i32(p)
        cnt = r.i32(p + 4)
        ti.data["ManagedFieldCount"] = cnt
        p += 8
        if cnt is not None and 0 <= cnt <= 4096:
            for _ in range(cnt):
                ti.fields.append({"TypeInfo": r.u32(p), "Offset": r.i32(p + 4)})
                p += 8
    elif kind == 15:                                         # tkInterface
        ti.data["IntfParent"] = r.u32(p)
        ti.data["IntfFlags"] = r.u8(p + 4)
        ti.data["GUID"] = _guid(r.bytes(p + 5, 16))
        p += 21
        ti.unit, p = _unitname(r, p)
    elif kind == 16:                                         # tkInt64
        ti.data["MinValue"] = r.i64(p)
        ti.data["MaxValue"] = r.i64(p + 8)
        p += 16
    elif kind == 17:                                         # tkDynArray
        ti.data["ElSize"] = r.i32(p)
        ti.data["ElType"] = r.u32(p + 4)
        ti.data["VarType"] = r.i32(p + 8)
        ti.data["ElType2"] = r.u32(p + 12)
        p += 16
        ti.unit, p = _unitname(r, p)
    # tkLString / tkWString / tkVariant carry no TTypeData at all.

    ti.end = p
    return ti


def _parse_props(r, p):
    """TPropData: Word count followed by that many TPropInfo records."""
    count = r.u16(p)
    p += 2
    props = []
    if count is None or count > 4096:
        return props, p
    for _ in range(count):
        pi = {
            "addr": p,
            "PropType": r.u32(p),
            "GetProc": r.u32(p + 4),
            "SetProc": r.u32(p + 8),
            "StoredProc": r.u32(p + 12),
            "Index": r.i32(p + 16),
            "Default": r.i32(p + 20),
            "NameIndex": r.i16(p + 24),
        }
        name, p2 = r.shortstr(p + 26)
        if not is_identifier(name):
            return props, p
        pi["Name"] = name
        pi["end"] = p2
        props.append(pi)
        p = p2
    return props, p


def _guid(b):
    if len(b) != 16:
        return None
    d1, d2, d3 = struct.unpack("<IHH", b[:8])
    return "{%08X-%04X-%04X-%s-%s}" % (
        d1, d2, d3, b[8:10].hex().upper(), b[10:].hex().upper())


# --------------------------------------------------------------------- VMTs

class Vmt(object):
    def __init__(self, addr, layout=DEFAULT_LAYOUT):
        self.addr = addr             # the class pointer value itself
        self.header = addr - layout.header_size
        self.name = None
        self.slots = {}              # slot name -> raw dword
        self.instance_size = None
        self.parent = None           # parent VMT address (dereferenced)
        self.parent_ptr = None       # address of the PClass cell
        self.methods = []            # published methods: name + address
        self.dynamic = []            # dynamic/message methods
        self.fields = []             # published fields
        self.field_classes = []      # class table backing the field list
        self.interfaces = []
        self.virtuals = []           # (slot_index, address) beyond -4
        self.vtable_end = addr       # one past the last virtual slot
        self.regions = []            # (start, end, label) owned by this VMT

    def __repr__(self):
        return "<Vmt %08x %s>" % (self.addr, self.name)


def parse_vmt(r, addr):
    """Parse the VMT whose class pointer is `addr`.  None if it is not one."""
    layout = r.layout
    if r.ptr(addr - layout.header_size) != addr:        # vmtSelfPtr must self-ref
        return None
    name_ptr = r.ptr(addr - layout.header_size + layout.class_name_offset)
    if name_ptr is None or not r.is_mapped(name_ptr):
        return None
    name, _ = r.shortstr(name_ptr)
    if not is_identifier(name):
        return None

    v = Vmt(addr, layout)
    v.name = name
    for off, slot in VMT_NEG:
        v.slots[slot] = r.u32(addr + off)
    v.instance_size = v.slots["vmtInstanceSize"]
    v.parent_ptr = addr - 36
    pp = v.slots["vmtParent"]
    if pp and r.is_mapped(pp):
        v.parent = r.u32(pp)

    v.regions.append((name_ptr, name_ptr + 1 + len(name), "ClassName"))

    _parse_method_table(r, v)
    _parse_dynamic_table(r, v)
    _parse_field_table(r, v)
    _parse_intf_table(r, v)
    _parse_vtable(r, v)
    return v


def _parse_method_table(r, v):
    """Word count, then per entry: Word size, Pointer addr, ShortString name."""
    p = v.slots.get("vmtMethodTable")
    if not p or not r.is_mapped(p):
        return
    start = p
    count = r.u16(p)
    if count is None or count > 4096:
        return
    p += 2
    for _ in range(count):
        size = r.u16(p)
        if size is None or size < 7:
            return
        addr = r.u32(p + 2)
        name, _ = r.shortstr(p + 6)
        if not is_identifier(name):
            return
        v.methods.append({"addr": addr, "name": name, "entry": p, "size": size})
        p += size
    v.regions.append((start, p, "MethodTable"))


def _parse_dynamic_table(r, v):
    """Word count, Count SmallInt message ids, then Count code pointers."""
    p = v.slots.get("vmtDynamicTable")
    if not p or not r.is_mapped(p):
        return
    count = r.u16(p)
    if count is None or count > 4096:
        return
    ids = [r.i16(p + 2 + 2 * i) for i in range(count)]
    base = p + 2 + 2 * count
    for i, mid in enumerate(ids):
        v.dynamic.append({"id": mid, "addr": r.u32(base + 4 * i)})
    v.regions.append((p, base + 4 * count, "DynamicTable"))


def _parse_field_table(r, v):
    """Word count, PFieldClassTable, then per entry: DWord offset, Word class
    index, ShortString name."""
    p = v.slots.get("vmtFieldTable")
    if not p or not r.is_mapped(p):
        return
    start = p
    count = r.u16(p)
    ctab = r.u32(p + 2)
    if count is None or count > 4096:
        return
    p += 6
    for _ in range(count):
        off = r.u32(p)
        idx = r.u16(p + 4)
        name, p2 = r.shortstr(p + 6)
        if not is_identifier(name):
            return
        v.fields.append({"offset": off, "class_index": idx, "name": name,
                         "entry": p})
        p = p2
    v.regions.append((start, p, "FieldTable"))

    if ctab and r.is_mapped(ctab):
        n = r.u16(ctab)
        if n is not None and n <= 4096:
            v.field_classes = [r.u32(ctab + 2 + 4 * i) for i in range(n)]
            v.regions.append((ctab, ctab + 2 + 4 * n, "FieldClassTable"))


def _parse_intf_table(r, v):
    """Integer count then 28-byte TInterfaceEntry records."""
    p = v.slots.get("vmtIntfTable")
    if not p or not r.is_mapped(p):
        return
    count = r.i32(p)
    if count is None or not (0 < count <= 1024):
        return
    for i in range(count):
        e = p + 4 + 28 * i
        v.interfaces.append({
            "guid": _guid(r.bytes(e, 16)), "vtable": r.u32(e + 16),
            "offset": r.i32(e + 20), "getter": r.u32(e + 24), "entry": e})
    v.regions.append((p, p + 4 + 28 * count, "IntfTable"))

    # Each entry points at a vtable of thunk addresses.  That array is data,
    # and unlike the entry table it is not otherwise covered -- leaving it
    # bare lets linear sweep disassemble a run of pointers as code and walk
    # from there into the VMT behind it.
    for entry in v.interfaces:
        vtable = entry["vtable"]
        if not vtable or not r.is_mapped(vtable):
            continue
        slots = 0
        while slots < 1024:
            target = r.u32(vtable + 4 * slots)
            if not target or not r.is_code(target):
                break
            slots += 1
        if slots:
            v.regions.append((vtable, vtable + 4 * slots, "IntfVTable"))


def _parse_vtable(r, v):
    """Walk forward from the class pointer while the dwords still look like
    code addresses.  The first non-code dword ends the virtual table."""
    p = v.addr
    i = 0
    while i < 4096:
        val = r.u32(p)
        if val is None or not r.is_mapped(val) or not r.is_code(val):
            break
        v.virtuals.append((i, val))
        p += 4
        i += 1
    v.vtable_end = p


# ------------------------------------------------------------------ scanner

def scan(r, start, end, progress=None):
    """Find every VMT and TTypeInfo record in [start, end).

    Both structures have a self-referencing pointer that makes them cheap and
    almost false-positive free to spot: a VMT stores its own address at -76,
    and the compiler emits each TTypeInfo behind a PPTypeInfo cell that points
    four bytes ahead at the record itself.
    """
    vmts, typeinfos = {}, {}
    step = max(1, (end - start) // 100)
    for addr in range(start, end):
        if progress and (addr - start) % step == 0:
            if progress(addr - start, end - start) is False:
                break
        val = r.u32(addr)
        if val is None:
            continue
        if val == addr + r.layout.header_size:
            v = parse_vmt(r, val)
            if v:
                vmts[v.addr] = v
        elif val == addr + 4:
            ti = parse_typeinfo(r, addr + 4)
            if ti:
                ti.ptr_addr = addr
                typeinfos[ti.addr] = ti
    return vmts, typeinfos


def cluster(addrs, gap=0x200):
    """Group sorted (start, end) spans that sit within `gap` bytes."""
    spans = sorted(addrs)
    if not spans:
        return []
    out = []
    cs, ce = spans[0]
    for s, e in spans[1:]:
        if s - ce <= gap:
            ce = max(ce, e)
        else:
            out.append((cs, ce))
            cs, ce = s, e
    out.append((cs, ce))
    return out


# ------------------------------------------------- property accessor decoding

PROP_FIELD = 0xFF000000
PROP_VIRTUAL = 0xFE000000


def decode_accessor(value):
    """TPropInfo Get/Set/StoredProc: a tagged dword.

    $FF...  -> the property maps straight onto an instance field
    $FE...  -> a virtual method; the low word is a signed byte offset
               from the class pointer, not a slot index
    else    -> the address of a static method
    """
    if value is None:
        return ("none", None)
    if value == 0:
        return ("none", None)
    tag = value & 0xFF000000
    if tag == PROP_FIELD:
        return ("field", value & 0x00FFFFFF)
    if tag == PROP_VIRTUAL:
        # SmallInt byte offset from the class pointer, per TypInfo.pas:
        # PPointer(PInteger(Instance)^ + SmallInt(GetProc))^
        off = value & 0xFFFF
        return ("virtual", off - 0x10000 if off > 0x7FFF else off)
    return ("static", value)
