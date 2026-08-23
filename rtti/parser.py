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

# The eleven data slots, in order from the start of the VMT header. Their
# order has never changed; only the header's distance from the class pointer
# has, because TObject gained virtual methods. Deriving the offsets from the
# layout rather than writing them down is what makes one build read every era:
# a table hardcoded to the 76-byte header reads a Delphi 2009 binary's slots
# twelve bytes off and finds no tables at all.
DATA_SLOT_NAMES = [
    "vmtSelfPtr", "vmtIntfTable", "vmtAutoTable", "vmtInitTable",
    "vmtTypeInfo", "vmtFieldTable", "vmtMethodTable", "vmtDynamicTable",
    "vmtClassName", "vmtInstanceSize", "vmtParent",
]

# The standard TObject virtual slots, newest first. Each era appends to the
# END of this list conceptually -- new methods are inserted just after
# vmtParent, pushing nothing -- so an era with N virtuals uses the LAST N
# names, and the shared ones keep the same offsets they always had.
# Delphi 2 has the final five; Delphi 3 added SafeCallException,
# AfterConstruction and BeforeDestruction; Delphi 2009 added Equals,
# GetHashCode and ToString.
STD_METHOD_NAMES = [
    "Equals", "GetHashCode", "ToString",
    "SafeCallException", "AfterConstruction", "BeforeDestruction",
    "Dispatch", "DefaultHandler", "NewInstance", "FreeInstance", "Destroy",
]

VMT_HEADER_SIZE = 76        # Delphi 3 - 2007 only; prefer layout.header_size


def data_slots(layout):
    """[(offset from the class pointer, slot name)] for this layout."""
    return [(-layout.header_size + i * layout.ptr_size, name)
            for i, name in enumerate(DATA_SLOT_NAMES)]


def std_methods(layout):
    """[(offset from the class pointer, method name)] for this layout.

    An era with more virtuals than we have names for gets positional names for
    the extras rather than a wrong name borrowed from a neighbouring era.
    """
    n = layout.n_virtuals
    names = STD_METHOD_NAMES[-n:] if n <= len(STD_METHOD_NAMES) else (
        ["Virtual%d" % i for i in range(n - len(STD_METHOD_NAMES))]
        + STD_METHOD_NAMES)
    return [(-(len(names) - i) * layout.ptr_size, name)
            for i, name in enumerate(names)]


def header_sizes(ptr_size=4):
    """Every plausible VMT header size, for probes that have no layout yet."""
    return [(Layout.DATA_SLOTS + n) * ptr_size for n in Layout.VIRTUAL_COUNTS]


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
        layouts = [Layout(ptr_size, n) for n in Layout.VIRTUAL_COUNTS]
        # One pass over the window finds the self-referencing addresses for
        # every candidate header size at once; scoring then only touches those.
        by_size = {}
        for layout in layouts:
            by_size.setdefault(layout.header_size, []).append(layout)
        scores = {}
        for start, end in ranges:
            limit = min(end, start + window)
            for addr in self_pointers(reader, start, limit, by_size.keys(),
                                      step=ptr_size, width=ptr_size):
                val = read(addr)
                if val is None:
                    continue
                for layout in by_size[val - addr]:
                    name_ptr = read(addr + layout.class_name_offset)
                    if name_ptr is None or not reader.is_mapped(name_ptr):
                        continue
                    name, _ = reader.shortstr(name_ptr)
                    if is_identifier(name):
                        scores[layout] = scores.get(layout, 0) + 1
        for layout in layouts:
            score = scores.get(layout, 0)
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


_TYPECODES = {4: "I", 8: "Q"}

# Bytes pulled out of the view at a time by `self_pointers`. Small enough that
# an early-exiting caller stops after copying a little, large enough that the
# per-chunk overhead is lost in the noise.
_CHUNK = 0x10000


def self_pointers(reader, start, end, deltas, step=1, width=4):
    """Yield, in ascending order, the addresses in [start, end) that point at
    themselves.

    An address qualifies when the little-endian integer of `width` bytes
    stored there equals the address plus one of `deltas`. Both Delphi
    structures announce themselves that way -- a VMT keeps its own address one
    header back, and a TTypeInfo record sits four bytes past a cell pointing
    at it -- so this one test is what every scan and probe here is built on,
    and it is the only thing the plugin does that is O(image size).

    Asking the reader for each address costs about 250 ns per byte of code:
    a second of Python on a four-megabyte code section, holding the GIL while
    the rest of analysis waits on it. Pulling the bytes out in blocks and
    walking them as machine arrays of integers is the same comparison against
    the same bytes, at about a sixth of the cost.

    A candidate may begin at any byte offset, so each block is walked once per
    offset within the word and the hits merged; the addresses whose word would
    run off the end of the block go through the reader, which is also the
    fallback for a block that cannot be read in one piece. Yielding block by
    block keeps a caller that stops at the first hit from paying for the rest.
    """
    read = reader.u32 if width == 4 else reader.u64
    deltas = frozenset(deltas)
    typecode = _TYPECODES.get(width)
    block = max(_CHUNK, width)
    for base in range(start, end, block):
        stop = min(base + block, end)
        data = reader.bytes(base, stop - base) if typecode else b""
        if len(data) != stop - base:
            for addr in range(base, stop, step):
                val = read(addr)
                if val is not None and val - addr in deltas:
                    yield addr
            continue
        hits = []
        view = memoryview(data)
        for offset in range(0, width, step):
            count = (len(data) - offset) // width
            if count <= 0:
                continue
            words = view[offset:offset + width * count].cast(typecode)
            addr = base + offset
            for word in words:
                if word - addr in deltas:
                    hits.append(addr)
                addr += width
        # The addresses at the end of the block, whose word the arrays could
        # not cover, on the same address grid the caller asked for.
        tail = stop - width + 1
        tail += -(tail - start) % step
        for addr in range(max(base, tail), stop, step):
            val = read(addr)
            if val is not None and val - addr in deltas:
                hits.append(addr)
        hits.sort()
        for addr in hits:
            yield addr


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
        self.dynamic_table = None    # geometry of the table behind `dynamic`
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
    for off, slot in data_slots(layout):
        v.slots[slot] = r.ptr(addr + off)
    v.instance_size = v.slots["vmtInstanceSize"]
    v.parent_ptr = addr - layout.header_size + 10 * layout.ptr_size
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
    entries = []
    for i, mid in enumerate(ids):
        addr = r.u32(base + 4 * i)
        # Every entry in a real dynamic table is a handler address. If any of
        # them does not point at code, the slot was read from the wrong offset
        # and the whole table is noise: a misread slot readily yields thousands
        # of entries pointing outside the image, which the count cap alone does
        # not catch. Claiming those names is worse than recovering none, so
        # discard the table rather than salvage it.
        if addr is None or not r.is_code(addr):
            return
        entries.append({"id": mid, "addr": addr})
    v.dynamic.extend(entries)
    # The geometry, not just the entries: the table is two parallel arrays
    # whose lengths are only known here, and typing the pointer array is what
    # turns the handlers into referenced code rather than loose addresses.
    v.dynamic_table = {"addr": p, "count": count, "ids": p + 2,
                       "handlers": base, "end": base + 4 * count}
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
            "offset": r.i32(e + 20), "getter": r.u32(e + 24), "entry": e,
            "slots": 0})
    v.regions.append((p, p + 4 + 28 * count, "IntfTable"))

    # Each entry points at a vtable of thunk addresses.  That array is data,
    # and unlike the entry table it is not otherwise covered -- leaving it
    # bare lets linear sweep disassemble a run of pointers as code and walk
    # from there into the VMT behind it.  Its length is kept on the entry as
    # well as in the region, because that is what the applier has to declare
    # for the thunks in it to be referenced at all.
    #
    # A class implementing several interfaces emits their vtables one after
    # another, and walking the pointers cannot find the boundary between two
    # of them -- every entry of the next table is a code address too.  The
    # next table's own address is that boundary, so bound the walk with it.
    # Without it the first vtable is declared over the second, and the array
    # defined for the second then erases the first.
    starts = sorted({e["vtable"] for e in v.interfaces
                     if e["vtable"] and r.is_mapped(e["vtable"])})
    for entry in v.interfaces:
        vtable = entry["vtable"]
        if not vtable or not r.is_mapped(vtable):
            continue
        limit = next((s for s in starts if s > vtable), None)
        limit = 1024 if limit is None else min(1024, (limit - vtable) // 4)
        slots = 0
        while slots < limit:
            target = r.u32(vtable + 4 * slots)
            if not target or not r.is_code(target):
                break
            slots += 1
        entry["slots"] = slots
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
    almost false-positive free to spot: a VMT stores its own address one header
    back, at whatever distance this layout puts it, and the compiler emits each
    TTypeInfo behind a PPTypeInfo cell that points four bytes ahead at the
    record itself.

    Finding those pointers is `self_pointers`' job; parsing what they point at
    happens here, on the handful of addresses that survive. The range is
    walked in chunks so a caller with a progress callback can watch it, and
    cancel it, part way through.
    """
    header_size = r.layout.header_size
    candidates = (header_size, 4)
    vmts, typeinfos = {}, {}
    step = max(1, (end - start) // 100)
    for chunk in range(start, end, step):
        if progress and progress(chunk - start, end - start) is False:
            break
        for addr in self_pointers(r, chunk, min(chunk + step, end), candidates):
            val = r.u32(addr)
            if val == addr + header_size:
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
