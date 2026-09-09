"""Pure parser for Delphi (2..13/x86) RTTI, VMT and metadata tables.

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
    # Delphi 2009 appended tkUString and 2010 the three after it; 10.4 added
    # tkMRecord. A parser that stops at tkDynArray does not merely miss those
    # records, it mistypes every parameter and property that refers to one:
    # UnicodeString is the string type of every modern binary, and an
    # unresolved PPTypeInfo falls back to a plain integer.
    18: "tkUString", 19: "tkClassRef", 20: "tkPointer", 21: "tkProcedure",
    22: "tkMRecord",
}

ORD_TYPES = {0: "otSByte", 1: "otUByte", 2: "otSWord", 3: "otUWord",
             4: "otSLong", 5: "otULong"}
FLOAT_TYPES = {0: "ftSingle", 1: "ftDouble", 2: "ftExtended", 3: "ftComp",
               4: "ftCurr"}
METHOD_KINDS = {0: "mkProcedure", 1: "mkFunction", 2: "mkConstructor",
                3: "mkDestructor", 4: "mkClassProcedure", 5: "mkClassFunction",
                6: "mkClassConstructor", 7: "mkClassDestructor",
                8: "mkOperatorOverload"}
# TParamFlags, one bit per TParamFlag ordinal. pfResult is the seventh and
# marks the hidden parameter a function returning a managed or oversized type
# is compiled with; it never appears in a tkMethod record, because that shape
# spells the result out separately, but roughly one extended-RTTI parameter in
# forty carries it. The eighth bit is unused by every compiler in the corpus.
PARAM_FLAGS = [(0x01, "pfVar"), (0x02, "pfConst"), (0x04, "pfArray"),
               (0x08, "pfAddress"), (0x10, "pfReference"), (0x20, "pfOut"),
               (0x40, "pfResult")]

#: TCallConv, as TVmtMethodEntryTail.CC records it.
CALL_CONVS = {0: "ccReg", 1: "ccCdecl", 2: "ccPascal", 3: "ccStdCall",
              4: "ccSafeCall"}

# TVmtMethodExEntry.Flags. The field is usually described as holding the
# member's visibility, and it does not: every member of TObject is declared
# public in System.pas, yet a Delphi 10.1 build gives Create $44, Destroy $4D,
# ClassName $43 and Free $42. What the low THREE bits hold is the kind of
# member, and the entries corroborate that exactly -- across all 15,351
# extended entries in the corpus, without a single exception:
#
#   1  static        no Self parameter at all (`class function ...; static`)
#   2  method        Self typed as the instance
#   3  class method  Self present but with no ParamType: it is the metaclass
#   4  constructor   Self typed as the instance
#   5  destructor    Self typed as the instance, and named Destroy every time
#
# Which of the three shapes Self has is the fact the applier needs, and it is
# the one the entries prove rather than the one the field is named after.
# Visibility is in there too, in bits 5 and 6 -- $02/$22/$42/$62 are the four
# TMemberVisibility values -- but nothing here has a use for it.
METHOD_KIND_MASK = 0x07
MK_STATIC, MK_METHOD, MK_CLASS_METHOD = 1, 2, 3
MK_CONSTRUCTOR, MK_DESTRUCTOR = 4, 5

# Bits 3, 4 and 7 say how the method is dispatched and hence how to read
# VirtualIndex.  Every one of the 15,351 extended entries in the corpus has
# exactly one of bit 3 and bit 4 set, or neither and then VirtualIndex is the
# sentinel -- the three cases partition the entries with no overlap and no
# remainder, which is what makes reading the field safe:
#
#   bit 3  the method occupies a vtable slot and VirtualIndex is that slot
#   bit 4  the method is dispatched dynamically and VirtualIndex is its
#          dynamic-table id -- a negative counter for a plain `dynamic`
#          method, the message id for a `message` one.  168/168 of these ids
#          appear in the class's own or an inherited dynamic table, against
#          the same handler address the entry itself carries.
#   bit 7  the method is abstract.  563/563 of these have a CodeAddress that
#          is a five-byte `jmp rel32` to one single address per binary --
#          System's @AbstractError -- and the vtable slot VirtualIndex names
#          holds that same shared address rather than the thunk.  So the index
#          is right and the slot is not the method: naming what sits there
#          would give @AbstractError one arbitrary class's method name.
#
# Reading the field without bit 4 is what makes a plain dynamic method look
# like a vtable slot that resolves to the wrong function, and reading it
# without bit 7 makes every abstract declaration look like a mismatch; between
# them those two are the whole of the ~20% of non-sentinel entries whose index
# does not lead back to the entry's own code address.
FLAG_VIRTUAL = 0x08
FLAG_DYNAMIC = 0x10
FLAG_ABSTRACT = 0x80


def no_slot_index(layout):
    """The VirtualIndex a method occupying no vtable slot carries.

    One below the last standard TObject virtual, so it moves with the era:
    -12 where TObject has eleven virtuals, -9 where it has eight.  Hardcoding
    a value would silently turn every non-virtual entry of a 2009 binary into
    a plausible-looking slot index in a Delphi 3 one.
    """
    return -(layout.n_virtuals + 1)


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

# Delphi 2's header is the same list with its first two slots absent, so the
# rest keep their order and only their distance from the class pointer moves.
# Interfaces arrive in Delphi 3, which is why there is no vmtIntfTable; the
# self-pointer arrives with them, and its absence is what makes this era
# invisible to a scanner built on that one test -- see `class_anchors`.
#
# Measured on innosetup/compil32_1.exe: nine data slots and four virtuals, so
# the header is 52 bytes and the slots run -52 vmtAutoTable, -48 vmtInitTable,
# -44 vmtTypeInfo, -40 vmtFieldTable, -36 vmtMethodTable, -32 vmtDynamicTable,
# -28 vmtClassName, -24 vmtInstanceSize, -20 vmtParent.  Four independent
# classes corroborate it: the record at -44 is a tkClass whose name matches the
# class exactly, the instance sizes are right (TPersistent 4, TComponent $20,
# TStringList $28) and the parent chain resolves.
DATA_SLOT_NAMES_D2 = [name for name in DATA_SLOT_NAMES
                      if name not in ("vmtSelfPtr", "vmtIntfTable")]

# The subset of those that address a table of this class's own. Everything else
# in the header either is the class pointer, counts rather than addresses, or
# points outside the class entirely -- see `_parse_vtable`, which bounds the
# virtual table by the nearest of these.
TABLE_SLOT_NAMES = [
    "vmtIntfTable", "vmtAutoTable", "vmtInitTable", "vmtTypeInfo",
    "vmtFieldTable", "vmtMethodTable", "vmtDynamicTable", "vmtClassName",
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
            for i, name in enumerate(layout.data_slot_names)]


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
    return sorted({layout.header_size for layout in Layout.variants(ptr_size)})


class Layout(object):
    """The dimensions of one Delphi RTTI dialect.

    Only the numbers change between versions, never the shape of the tables,
    so a descriptor threaded through the reader covers every era without
    duplicating any parsing logic.

    Two things move.  The number of standard TObject virtual slots grew as
    TObject itself gained virtual methods -- five in early Delphi 3, eight
    through 2007, eleven from 2009 -- which is why a parser hardcoded to a
    76-byte header sees nothing at all in a modern binary, 32-bit included.
    And Delphi 2 has two fewer data slots than everything after it, so for
    that era even the slot *order* differs; see DATA_SLOT_NAMES_D2.
    """

    #: standard TObject virtual slots by era, for the eleven-slot header
    VIRTUAL_COUNTS = (5, 8, 11, 14)
    #: Delphi 2's, for the nine-slot one
    D2_VIRTUALS = 4

    def __init__(self, ptr_size=4, n_virtuals=8, data_slot_names=None):
        self.ptr_size = ptr_size
        self.n_virtuals = n_virtuals
        self.data_slot_names = list(data_slot_names or DATA_SLOT_NAMES)
        self.header_size = (len(self.data_slot_names) +
                            n_virtuals) * ptr_size
        self.has_self_ptr = "vmtSelfPtr" in self.data_slot_names
        # Delphi 3 introduced a level of indirection that Delphi 2 does not
        # have: every reference from one record to another became a cell
        # holding the target's address rather than the address itself.
        # vmtParent became a PClass, vmtTypeInfo a cell, and TManagedField's
        # TypeRef the PPTypeInfo that the rest of this file dereferences
        # twice.  It arrived with vmtSelfPtr and for the same reason -- the
        # linker can then discard a record and leave the cell nil -- so the
        # one slot decides both, and getting it wrong is silent: reading a
        # Delphi 2 parent slot as a PClass dereferences the parent's first
        # virtual method and finds no class at all.
        self.indirect_refs = self.has_self_ptr

    @classmethod
    def variants(cls, ptr_size=4):
        """Every dialect to try when nothing is known about the binary yet."""
        return ([cls(ptr_size, cls.D2_VIRTUALS, DATA_SLOT_NAMES_D2)] +
                [cls(ptr_size, n) for n in cls.VIRTUAL_COUNTS])

    def __repr__(self):
        return "<Layout ptr=%d slots=%d virtuals=%d header=%d>" % (
            self.ptr_size, len(self.data_slot_names), self.n_virtuals,
            self.header_size)

    def slot_offset(self, name):
        """Offset of one data slot from the class pointer.

        Asking the slot list rather than counting from vmtSelfPtr is what
        keeps the eras apart: vmtClassName is the ninth slot from Delphi 3
        onwards and the seventh in Delphi 2, and the difference is exactly the
        two slots that era does not have.
        """
        return (self.data_slot_names.index(name) * self.ptr_size -
                self.header_size)

    @property
    def class_name_offset(self):
        """vmtClassName's offset from the START of the header, not the class
        pointer -- which is what the probes that have only a header address
        can use."""
        return self.slot_offset("vmtClassName") + self.header_size


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
        layouts = Layout.variants(ptr_size)
        # One pass over the window finds the self-referencing addresses for
        # every candidate header size at once; scoring then only touches those.
        by_size = {}
        for layout in layouts:
            if layout.has_self_ptr:
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
        # The eras with no self-pointer cannot be scored that way at all, so
        # they are scored on the anchor they do have. Both scores count the
        # same thing -- classes whose header reads as a class -- which is what
        # makes them comparable, and the wrong-era score is not merely lower
        # but zero: the shape test scores 0 on every one of the 97 corpus
        # binaries that is not Delphi 2, because `linked_class_anchors`
        # discards a candidate that is not part of a hierarchy.
        for layout in layouts:
            if layout.has_self_ptr:
                continue
            score = 0
            for start, end in ranges:
                score += len(linked_class_anchors(
                    reader, start, min(end, start + window), layout))
            scores[layout] = score
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


def is_identifier(text, min_len=1, max_len=255):
    # The cap is the ShortString's own limit, not a guess at how long a name
    # ought to be. A nested generic instantiation spells out every type
    # argument fully qualified, so
    # TEnumerable<System.Generics.Collections.TPair<System.Messaging.
    # TMessageListenerMethod,System.Messaging.TMessageManager.TListenerData>>
    # is 133 characters of perfectly ordinary Delphi 12 class name; a shorter
    # cap silently discards the VMT and every method it publishes.
    if text is None or not (min_len <= len(text) <= max_len):
        return False
    # Delphi identifiers, plus '.' for qualified unit names, the compiler's
    # own decorations ('$', '@'), and the angle brackets and commas that
    # generic type names carry -- TArray<System.Byte> is a perfectly ordinary
    # RTTI name from 2010 onwards, and rejecting it discards a large share of
    # the type records in a modern binary.
    #
    # The backtick and the square brackets are two more of the compiler's own
    # decorations, and they are the whole of what a modern binary's VMT scan
    # was missing.  An anonymous method compiles to a hidden class holding the
    # captured variables, and the compiler names it after where it was written:
    #
    #     @TList`1.Pack[0]$ActRec<System.Classes.TComponent>
    #
    # `1 is the generic arity of the enclosing type, [0] the ordinal of the
    # closure within the enclosing routine -- XE2 spells that same ordinal
    # $23$ instead, which is why only the newer samples needed the brackets --
    # and $ActRec marks the activation record.  These are ordinary
    # TInterfacedObject descendants with a real VMT, an interface table and a
    # tkClass record; rejecting the name discarded 69 of imagewriter's 815
    # classes, 65 of httpdiag's 652 and 49 of vcl_ad4d's 937, along with the
    # interface vtables behind them, which is exactly the set a competing
    # Ghidra plugin found and this one did not.
    return all(c.isalnum() or c in "_.$@<>,`[]" for c in text)


# ------------------------------------------- VMTs that carry no self-pointer

#: Shortest class name accepted from a header found by shape alone. A
#: one-character ShortString is a length byte and one letter, which unrelated
#: bytes produce constantly; no Delphi class is named that either.
MIN_CLASS_NAME = 2

#: Largest instance size accepted from such a header. Generous on purpose --
#: innosetup's TLZMA1SmallDecompressor really is 65,640 bytes -- so this only
#: stops an arbitrary dword from passing as a size.
MAX_INSTANCE_SIZE = 0x100000


def _class_head(r, addr, layout):
    """Read the header at class pointer `addr` as a VMT, on shape alone.

    Delphi 2 has no vmtSelfPtr, so there is no single word whose value proves
    what these bytes are; what proves it is that several slots have to agree
    with each other.  Three adjacent slots -- vmtClassName, vmtInstanceSize,
    vmtParent -- plus the standard virtuals behind the header give five
    independent conditions:

      * vmtClassName points at a ShortString that reads as an identifier
      * vmtInstanceSize is a plausible object size
      * every standard virtual slot holds a code address
      * vmtParent is nil, or points at a header that passes the first two
        tests itself
      * and if it does, the parent is no larger than the child, because a
        descendant only ever adds fields

    Returns {"name", "name_ptr", "instance_size", "parent"} or None.  `parent`
    is the parent's class pointer: this era stores it directly rather than
    through a PClass cell, so no dereference belongs here.
    """
    # Read at the candidate layout's width, not the reader's: detection asks
    # this before any layout has been settled on.
    ptr = layout.ptr_size
    read = r.u32 if ptr == 4 else r.u64
    name_ptr = read(addr + layout.slot_offset("vmtClassName"))
    if not name_ptr or not r.is_mapped(name_ptr):
        return None
    name, _ = r.shortstr(name_ptr)
    if not is_identifier(name, min_len=MIN_CLASS_NAME):
        return None
    size = read(addr + layout.slot_offset("vmtInstanceSize"))
    if size is None or not (ptr <= size <= MAX_INSTANCE_SIZE):
        return None
    for i in range(layout.n_virtuals):
        if not r.is_code(read(addr - (i + 1) * ptr)):
            return None
    parent = read(addr + layout.slot_offset("vmtParent"))
    if parent:
        if not r.is_mapped(parent):
            return None
        pname_ptr = read(parent + layout.slot_offset("vmtClassName"))
        if not pname_ptr or not r.is_mapped(pname_ptr):
            return None
        pname, _ = r.shortstr(pname_ptr)
        if not is_identifier(pname, min_len=MIN_CLASS_NAME):
            return None
        psize = read(parent + layout.slot_offset("vmtInstanceSize"))
        if psize is None or not (ptr <= psize <= size):
            return None
    return {"name": name, "name_ptr": name_ptr, "instance_size": size,
            "parent": parent}


def class_anchors(r, start, end, layout):
    """Yield (class pointer, head) for every plausible VMT in [start, end)
    under a layout with no self-pointer to key on.

    `_class_head` reads a dozen words and a ShortString, which is far too much
    to spend on every address, so a cheap test picks the addresses worth
    spending it on: vmtInstanceSize, a small positive integer where the great
    majority of dwords in a code section are not.  That is one comparison per
    candidate, made over the range as an array of machine integers for the
    same reason `self_pointers` does it, and it leaves about one address in
    fifty for the full check.

    Only the prefilter reads the block; `_class_head` goes back through the
    reader and reaches behind the candidate freely, so nothing is lost at a
    block boundary and the blocks do not need to overlap.
    """
    ptr = layout.ptr_size
    typecode = _TYPECODES.get(ptr)
    # vmtInstanceSize is one slot past vmtClassName in every era, so this one
    # word locates the whole header.
    size_off = layout.slot_offset("vmtInstanceSize")
    for base in range(start, end, _CHUNK):
        stop = min(base + _CHUNK, end)
        data = r.bytes(base, stop - base) if typecode else b""
        if len(data) != stop - base:
            addrs = range(base, stop, ptr)
        else:
            count = len(data) // ptr
            words = memoryview(data)[:ptr * count].cast(typecode)
            addrs = [base + ptr * i for i in range(count)
                     if ptr <= words[i] <= MAX_INSTANCE_SIZE]
        for addr in addrs:
            head = _class_head(r, addr - size_off, layout)
            if head is not None:
                yield addr - size_off, head


def linked_class_anchors(r, start, end, layout):
    """`class_anchors` reduced to the candidates that form a hierarchy.

    A single header-shaped run of words happens by accident all the time: 91
    of the 97 binaries in the corpus that are not Delphi 2 contain one, 92 in
    all, and they are indistinguishable one at a time -- the commonest is the
    RTL's own TObject header, whose class name, instance size and parent slots
    sit adjacent in every era too, just at a different distance.

    A class *hierarchy* does not happen by accident.  Every class but TObject
    names its parent, and that parent is another class in the same image, so
    genuine candidates form a connected forest while a coincidence stands
    alone.  Keeping only the candidates that name another candidate as parent
    or are named by one is the whole difference between a clean answer and a
    wrong one: it discards all 92 of those accidents, and of the 1,058
    genuine classes across the 23 Delphi 2 binaries it discards none.
    """
    heads = dict(class_anchors(r, start, end, layout))
    linked = set()
    for addr, head in heads.items():
        if head["parent"] in heads:
            linked.add(addr)
            linked.add(head["parent"])
    return sorted(linked)


def find_vmt(r, ranges, limit=None):
    """The first VMT in `ranges`, under whichever dialect finds one.

    Eligibility probes need this and have no layout yet, so every variant is
    tried and the reader's own layout is restored afterwards.  Trying only the
    self-pointer anchor is what made a Delphi 2 binary answer "not Delphi" and
    skip recovery entirely -- including the string constants the parser can
    already read out of it without any VMT at all.
    """
    saved = r.layout
    try:
        for layout in Layout.variants(r.ptr_size):
            r.layout = layout
            for start, end in ranges:
                stop = end if limit is None else min(end, start + limit)
                if layout.has_self_ptr:
                    anchors = (r.ptr(a) for a in self_pointers(
                        r, start, stop, (layout.header_size,),
                        step=layout.ptr_size, width=layout.ptr_size))
                else:
                    anchors = linked_class_anchors(r, start, stop, layout)
                for addr in anchors:
                    v = parse_vmt(r, addr)
                    if v is not None:
                        return v
    finally:
        r.layout = saved
    return None


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
    elif kind in (14, 22):                       # tkRecord / tkMRecord
        # A managed record leads with exactly the plain record's shape and
        # only then adds the operator table Delphi 10.4 introduced, which
        # nothing here reads, so the two share this branch and the record
        # ends -- conservatively -- at the last managed field.
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
    elif kind in (19, 20):                       # tkClassRef / tkPointer
        # One PPTypeInfo naming what the reference or pointer points at:
        # InstanceType for a metaclass, RefType for a pointer.
        ti.data["RefType"] = r.ptr(p)
        p += r.layout.ptr_size
    elif kind == 21:                                         # tkProcedure
        ti.data["Signature"], p = _proc_signature(r, p)
    # tkLString / tkWString / tkVariant / tkUString carry no TTypeData at all.

    ti.end = p
    return ti


#: TProcedureSignature.Flags when the compiler published no signature at all.
NO_SIGNATURE = 0xFF


def _proc_signature(r, p):
    """TProcedureSignature, the body of a tkProcedure record.

        Byte        Flags          $FF when there is no signature to read
        Byte        CC             TCallConv
        PPTypeInfo  ResultType
        Byte        ParamCount
        TProcedureParam[ParamCount]

    TProcedureParam is a Byte of TParamFlags, a PPTypeInfo, a ShortString name
    and a TAttrData -- the same fields a method parameter has, minus the ParOff
    that only a method needs.
    """
    ptr = r.layout.ptr_size
    flags = r.u8(p)
    if flags is None or flags == NO_SIGNATURE:
        return None, p + 1
    sig = {"flags": flags, "cc": CALL_CONVS.get(r.u8(p + 1), r.u8(p + 1)),
           "result_type": r.ptr(p + 2), "params": []}
    count = r.u8(p + 2 + ptr)
    p += 3 + ptr
    if count is None:
        return sig, p
    for _ in range(count):
        pflags = r.u8(p)
        name, q = r.shortstr(p + 1 + ptr)
        end = _attrdata_end(r, q) if name is not None else None
        if pflags is None or end is None:
            return sig, p
        sig["params"].append({
            "flags": pflags,
            "flag_names": [n for bit, n in PARAM_FLAGS if pflags & bit],
            "type": r.ptr(p + 1), "name": name})
        p = end
    return sig, p


def typeinfo_name(r, pptypeinfo):
    """The type name behind a PPTypeInfo cell, without parsing the record.

    Extended RTTI refers to a type by a cell holding a pointer to the record,
    never by the record's own address, so reaching the name takes two
    dereferences.  Only the kind byte and the ShortString after it are read:
    a caller describing every parameter of every method in a binary asks this
    tens of thousands of times, and parsing each record in full would parse
    every published property of every class along with it.

    A nil cell is not a failure. The compiler publishes no type for an
    untyped `var` parameter or for the metaclass Self of a class method, and
    None is the honest answer for those.
    """
    if not pptypeinfo or not r.is_mapped(pptypeinfo):
        return None
    ti = r.ptr(pptypeinfo)
    if not ti or not r.is_mapped(ti):
        return None
    kind = r.u8(ti)
    if not kind or kind not in TYPE_KINDS:
        return None
    name, _ = r.shortstr(ti + 1)
    return name if is_identifier(name) else None


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
        self.methods = []            # classic method table: name + address
        self.methods_ex = []         # extended method table, Delphi 2010+
        self.dynamic = []            # dynamic/message methods
        self.dynamic_table = None    # geometry of the table behind `dynamic`
        self.fields = []             # published fields
        self.field_classes = []      # class table backing the field list
        self.managed = []            # managed fields, from vmtInitTable
        self.init_table = None       # geometry of the table behind `managed`
        self.interfaces = []
        self.virtuals = []           # (slot_index, address) beyond -4
        self.vtable_end = addr       # one past the last virtual slot
        self.regions = []            # (start, end, label) owned by this VMT

    def __repr__(self):
        return "<Vmt %08x %s>" % (self.addr, self.name)


def parse_vmt(r, addr):
    """Parse the VMT whose class pointer is `addr`.  None if it is not one."""
    layout = r.layout
    if layout.has_self_ptr:
        if r.ptr(addr - layout.header_size) != addr:    # vmtSelfPtr self-refs
            return None
        name_ptr = r.ptr(addr - layout.header_size + layout.class_name_offset)
        if name_ptr is None or not r.is_mapped(name_ptr):
            return None
        name, _ = r.shortstr(name_ptr)
        if not is_identifier(name):
            return None
    else:
        # Delphi 2 keeps no self-pointer, so there is no one word to test;
        # the header has to prove itself by shape.
        head = _class_head(r, addr, layout)
        if head is None:
            return None
        name, name_ptr = head["name"], head["name_ptr"]

    v = Vmt(addr, layout)
    v.name = name
    for off, slot in data_slots(layout):
        v.slots[slot] = r.ptr(addr + off)
    v.instance_size = v.slots["vmtInstanceSize"]
    v.parent_ptr = addr + layout.slot_offset("vmtParent")
    pp = v.slots["vmtParent"]
    if pp and r.is_mapped(pp):
        # A PClass cell from Delphi 3 on, the parent's class pointer itself
        # before that.  Dereferencing a Delphi 2 parent slot reads the parent's
        # first virtual method and loses the whole hierarchy.
        v.parent = r.u32(pp) if layout.indirect_refs else pp

    v.regions.append((name_ptr, name_ptr + 1 + len(name), "ClassName"))

    _parse_init_table(r, v)
    _parse_method_table(r, v)
    _parse_dynamic_table(r, v)
    _parse_field_table(r, v)
    _parse_intf_table(r, v)
    _parse_vtable(r, v)
    return v


#: Longest TAttrData blob accepted. Attribute blobs of several hundred bytes
#: are ordinary -- System.Classes.TStrings.AddStrings publishes one -- so the
#: cap only stops a length read out of unrelated bytes from swallowing a
#: section.
MAX_ATTR_DATA = 0x4000

#: Extended entries accepted from one class before the table is called noise.
#: The largest genuine table in the corpus holds 123.
MAX_EX_METHODS = 4096


def _attrdata_end(r, addr):
    """One past the TAttrData blob at `addr`, or None if it is not one.

    The blob leads with a Word holding its own total length, that Word
    included, so an empty one is the two bytes `02 00`.  Reading the length
    rather than assuming the empty shape is the whole reason the parameter
    walk stays in step: a parser that steps a fixed two bytes is right only
    until it meets a parameter or a method carrying an attribute, and stock
    Delphi 12 emits method-level blobs of 281, 427 and 488 bytes.
    """
    n = r.u16(addr)
    if n is None or not (2 <= n <= MAX_ATTR_DATA):
        return None
    return addr + n


def parse_method_entry(r, addr):
    """One TVmtMethodEntry, the record both method arrays are built out of.

        Word        Len            total bytes of this entry, this Word included
        Pointer     CodeAddress
        ShortString Name
        --- TVmtMethodEntryTail, present only when Len leaves room for it ---
        Byte        Version
        Byte        CC             TCallConv
        PPTypeInfo  ResultType     nil for a procedure; two derefs to the record
        SmallInt    ParOff
        Byte        ParamCount
        TVmtMethodParam[ParamCount]
        TAttrData

    Len is what makes the record self-checking: a tail walk that ends anywhere
    other than exactly `addr + Len` read something that is not a method entry,
    and `complete` reports that.  A classic table entry carries no tail at all
    and is complete the moment the name ends on the declared boundary, which
    is how the same function serves both arrays.

    Returns None only when the head itself is not plausible, so a caller that
    merely wants the name and address is not held hostage by the tail.
    """
    ptr = r.layout.ptr_size
    size = r.u16(addr)
    if size is None or size < 3 + ptr:          # Len, CodeAddress, empty name
        return None
    name, p = r.shortstr(addr + 2 + ptr)
    if not is_identifier(name):
        return None
    m = {"addr": r.ptr(addr + 2), "name": name, "entry": addr, "size": size,
         "end": addr + size, "complete": p == addr + size,
         "cc": None, "result_type": None, "params": None}
    if p >= addr + size:
        return m

    m["version"] = r.u8(p)
    m["cc"] = CALL_CONVS.get(r.u8(p + 1), r.u8(p + 1))
    m["result_type"] = r.ptr(p + 2)             # PPTypeInfo cell, or nil
    m["par_off"] = r.i16(p + 2 + ptr)
    count = r.u8(p + 4 + ptr)
    p += 5 + ptr
    if count is None:
        return m

    # TVmtMethodParam: Byte Flags, PPTypeInfo ParamType, Word ParOff,
    # ShortString Name, TAttrData.  ParamType is nil for a parameter the
    # compiler publishes no type for -- an untyped `var`, or the metaclass
    # Self of a class method -- which is a fact about the declaration, not a
    # gap to be filled in.
    params = []
    for _ in range(count):
        flags = r.u8(p)
        pname, q = r.shortstr(p + 3 + ptr)
        if flags is None or pname is None:
            return m
        end = _attrdata_end(r, q)
        if end is None:
            return m
        params.append({
            "flags": flags,
            "flag_names": [n for bit, n in PARAM_FLAGS if flags & bit],
            "type": r.ptr(p + 1), "offset": r.u16(p + 1 + ptr),
            "name": pname, "entry": p, "end": end})
        p = end
    m["params"] = params
    m["complete"] = _attrdata_end(r, p) == addr + size
    return m


# The type kinds a field can have and still need the compiler's help to be
# created and destroyed. Those are exactly the fields vmtInitTable lists, and
# exactly the ones the published field table cannot describe: it carries only
# class-typed fields, so without this table every string, interface, dynamic
# array and Variant member of every class is missing from the struct.
MANAGED_KINDS = frozenset((10, 11, 12, 13, 14, 15, 17, 18, 22))

# The three of those that are stored inline in the instance rather than as one
# pointer-sized cell. Their size is not something this table says -- an inline
# tkArray of records occupies whatever its element type does, times its length
# -- so a member placed for one would overlap whatever follows it. They are
# accepted as evidence that the table parsed and then left unplaced.
INLINE_KINDS = frozenset((13, 14, 22))

#: Managed fields accepted from one class before the table is called noise.
MAX_MANAGED_FIELDS = 4096


def _managed_fields(r, p, count, instance_size, ptr):
    """Read `count` TManagedField records at `p`, or None if they are not.

        PPTypeInfo  TypeRef     two dereferences to the record, as everywhere
        NativeUInt  FldOffset

    Delphi 2 spells TypeRef as a plain PTypeInfo, one dereference, the same way
    it spells vmtParent and vmtTypeInfo; `Layout.indirect_refs` is that whole
    difference and reading it the modern way there lands on the first four
    bytes of the type's name.

    Every entry has to pass or the whole array is rejected.  There is no
    length or checksum on this table, and it is reached from a slot that is
    nil in most classes, so a half-plausible run is exactly what a wrongly
    guessed TTypeData shape produces -- and one accepted from the wrong offset
    would place a `string` member over the middle of a real field.

    The offset must land inside the instance and past the class pointer at
    offset zero, and the offsets must ascend: the compiler emits this list in
    field order, which held for every one of the 15,192 Delphi 3-and-later
    entries measured across the corpus without exception, and is one more
    thing unrelated bytes have no reason to do.
    """
    indirect = r.layout.indirect_refs
    fields = []
    last = -1
    for _ in range(count):
        ref = r.ptr(p)
        offset = r.ptr(p + ptr)
        if not ref or not r.is_mapped(ref):
            return None
        ti = r.ptr(ref) if indirect else ref
        if not ti or not r.is_mapped(ti):
            return None
        kind = r.u8(ti)
        if kind not in MANAGED_KINDS:
            return None
        # The name is read only to confirm a TTypeInfo is really there. It is
        # not required to be a Delphi identifier: the compiler names an
        # anonymous type after where it was declared, so the type of an
        # `array of T` field of TApplication is called ':TApplication.:1' and
        # the comparer inside a TList<T> ':{Generics.Collections}TList<...>.:1'.
        # Demanding an identifier rejected 346 otherwise perfect tables.
        name, _ = r.shortstr(ti + 1)
        if not name or not all(0x20 <= ord(c) < 0x7F for c in name):
            return None
        if offset is None or not (ptr <= offset < instance_size):
            return None
        if offset <= last:
            return None
        last = offset
        fields.append({"typeref": ref, "typeinfo": ti, "kind": kind,
                       "kind_name": TYPE_KINDS[kind], "type_name": name,
                       "offset": offset, "inline": kind in INLINE_KINDS,
                       "entry": p})
        p += 2 * ptr
    return fields


def _parse_init_table(r, v):
    """The managed fields, out of the record type vmtInitTable names.

    The slot points straight at a TTypeInfo, not at a PPTypeInfo cell, and the
    record describes the instance as a record: kind tkRecord, or tkMRecord
    once Delphi 10.4 gave records operators. Its name is empty for a class, so
    it is read and discarded; the TTypeData behind it is what matters.

    That TTypeData has two shapes in the wild, and nothing in the record says
    which one this is:

        A   DWord Size; DWord Count; entries at +8
        B   Word  ?;     DWord Size; DWord Count; entries at +10

    So both are tried and the entry array is validated in full under each
    before either is accepted, exactly as `parse_string` does for the two
    string-constant headers.  The shapes are not ambiguous in practice --
    across 9,388 classes in the corpus shape A accounts for 9,293 and shape B
    for none, and no class validates under both -- but "in practice" is what
    trying and checking is for; a version that emits B costs nothing here and
    would otherwise cost every managed field in the binary.
    """
    p = v.slots.get("vmtInitTable")
    if not p or not r.is_mapped(p):
        return
    if r.u8(p) not in (14, 22):
        return
    name, q = r.shortstr(p + 1)  # the record's own name; empty for a class
    if name is None:
        return
    ptr = r.layout.ptr_size
    size = v.instance_size or 0
    for head in (0, 2):
        base = q + head
        count = r.u32(base + 4)
        if count is None or not (0 < count <= MAX_MANAGED_FIELDS):
            continue
        fields = _managed_fields(r, base + 8, count, size, ptr)
        if fields is None:
            continue
        v.managed.extend(fields)
        end = base + 8 + count * 2 * ptr
        v.init_table = {"addr": p, "count": count, "entries": base + 8,
                        "rec_size": r.u32(base), "end": end}
        # The whole record, kind byte to last entry. Nothing else claims it --
        # these tables have no PPTypeInfo cell in front of them, so the
        # TypeInfo scan never sees one, and all 9,293 in the corpus are bytes
        # the sweep is otherwise free to disassemble.
        v.regions.append((p, end, "InitTable"))
        return


def _parse_method_table(r, v):
    """Word count, then that many TVmtMethodEntry records, then, from Delphi
    2010, a Word ExCount and that many TVmtMethodExEntry records."""
    p = v.slots.get("vmtMethodTable")
    if not p or not r.is_mapped(p):
        return
    start = p
    count = r.u16(p)
    if count is None or count > 4096:
        return
    p += 2
    for _ in range(count):
        m = parse_method_entry(r, p)
        if m is None:
            return
        v.methods.append(m)
        p += m["size"]
    v.regions.append((start, p, "MethodTable"))
    _parse_method_table_ex(r, v, p)


def _parse_method_table_ex(r, v, p):
    """The extended method array Delphi 2010 emits behind the classic one.

        Pointer   Entry -> TVmtMethodEntry
        Word      Flags          member kind, visibility and dispatch
        SmallInt  VirtualIndex   signed slot index from the class pointer

    VirtualIndex is an index, not an offset, and it is signed against the
    class pointer, so slot -1 is the last word of the VMT header and slot 0
    the first word past it.  That puts the standard TObject virtuals at -1
    down to -n_virtuals -- a Delphi 10.1 TObject reports Destroy at -1 and
    Equals at -11, exactly where `std_methods` places them -- and one below
    the last of them, `no_slot_index`, is the sentinel for a method that
    occupies no slot at all.  Flags says which of those readings applies; see
    FLAG_VIRTUAL and the two beside it.

    `p` is where the classic walk stopped, and that -- not a fixed offset from
    the table -- is where ExCount lives.  Classic entries are variable length,
    so reading the count at vmtMethodTable+2 is right only for the classes
    whose classic count is zero.  That is most classes in a modern binary but
    by no means all of them: three of the corpus's five Delphi 2010+ samples
    have classes with classic entries in front of their extended array.

    The stride is the pointer plus four, and the entries themselves are
    emitted outside the table, so each one is claimed as its own region.  This
    is where nearly all of a modern binary's method metadata is -- 4873
    entries against six classic ones on a Delphi 12 service -- and leaving it
    undeclared lets linear sweep disassemble it.

    Nothing marks a pre-2010 table as having no extended array; the Word after
    the classic entries then belongs to whatever the linker put next.  So the
    array is taken only when every entry in it resolves to a TVmtMethodEntry
    that parses, whose own Len accounts for exactly the bytes the walk
    consumed, and whose code address lands in a code section.  Unrelated bytes
    fail that on their first entry, and a partly plausible run is rejected
    whole rather than contributing invented names.
    """
    count = r.u16(p)
    if not count or count > MAX_EX_METHODS:
        return
    ptr = r.layout.ptr_size
    table, q = p, p + 2
    entries = []
    for _ in range(count):
        entry = r.ptr(q)
        flags = r.u16(q + ptr)
        if not entry or flags is None or not r.is_mapped(entry):
            return
        m = parse_method_entry(r, entry)
        if m is None or not m["complete"] or not r.is_code(m["addr"]):
            return
        m["flags"] = flags
        m["method_kind"] = flags & METHOD_KIND_MASK
        m["virtual_index"] = r.i16(q + ptr + 2)
        m["virtual"] = bool(flags & FLAG_VIRTUAL)
        m["dynamic"] = bool(flags & FLAG_DYNAMIC)
        m["abstract"] = bool(flags & FLAG_ABSTRACT)
        # Flags and VirtualIndex have to corroborate each other: an entry
        # dispatched neither through the vtable nor dynamically carries the
        # sentinel index, and one that is dispatched carries a real index
        # instead.  That holds for all 15,351 extended entries in the corpus,
        # and it is a much sharper test of "are these two words really a
        # TVmtMethodExEntry" than either field alone -- unrelated bytes have no
        # reason to agree with each other.
        if (m["virtual"] or m["dynamic"]) == (m["virtual_index"] ==
                                              no_slot_index(r.layout)):
            return
        entries.append(m)
        q += ptr + 4
    v.methods_ex.extend(entries)
    v.regions.append((table, q, "MethodTableEx"))
    for m in entries:
        v.regions.append((m["entry"], m["end"], "MethodEntry_" + m["name"]))


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
    code addresses.  The first non-code dword ends the virtual table.

    "Looks like a code address" is not on its own enough to find the end. A
    table that follows the vtable begins with count words, and two counts read
    as one dword can land in the code section -- `TMarshal`'s method table does
    exactly that, and the walk ran six bytes into it. Every table the header
    points at is at a known address, though, so the nearest one above the class
    pointer is a hard ceiling that no amount of plausible-looking data crosses.
    """
    # Only the slots that point at a table, and at the class pointer rather
    # than past it: a class declaring no virtuals of its own has its first
    # table sitting exactly there, which is `TMarshal`'s case and the one this
    # bound exists for. vmtSelfPtr is excluded because it *is* the class
    # pointer and would end the walk before it started; vmtInstanceSize is a
    # count rather than an address, and vmtParent points at another class.
    at_or_after = [v.slots.get(s) for s in TABLE_SLOT_NAMES]
    at_or_after = [p for p in at_or_after if p and p >= v.addr]
    ceiling = min(at_or_after) if at_or_after else None
    p = v.addr
    i = 0
    while i < 4096 and (ceiling is None or p < ceiling):
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

    A TTypeInfo record always has a self-referencing pointer that makes it
    cheap and almost false-positive free to spot: the compiler emits each one
    behind a PPTypeInfo cell that points four bytes ahead at the record
    itself.  From Delphi 3 a VMT announces itself the same way, storing its
    own address one header back at whatever distance this layout puts it, so
    one pass over the range finds both.

    Finding those pointers is `self_pointers`' job; parsing what they point at
    happens here, on the handful of addresses that survive. The range is
    walked in chunks so a caller with a progress callback can watch it, and
    cancel it, part way through.

    Delphi 2 has no such pointer in its VMTs, so that era needs a second pass
    keyed on the header's shape instead -- see `linked_class_anchors`.  It is
    a pass this scan does not want to pay for otherwise, and does not have to:
    which of the two applies is a property of the layout, already settled.
    """
    header_size = r.layout.header_size
    self_ptr = r.layout.has_self_ptr
    candidates = (header_size, 4) if self_ptr else (4,)
    vmts, typeinfos = {}, {}
    step = max(1, (end - start) // 100)
    for chunk in range(start, end, step):
        if progress and progress(chunk - start, end - start) is False:
            break
        for addr in self_pointers(r, chunk, min(chunk + step, end), candidates):
            val = r.u32(addr)
            if self_ptr and val == addr + header_size:
                v = parse_vmt(r, val)
                if v:
                    vmts[v.addr] = v
            elif val == addr + 4:
                ti = parse_typeinfo(r, addr + 4)
                if ti:
                    ti.ptr_addr = addr
                    typeinfos[ti.addr] = ti
    if not self_ptr:
        for addr in linked_class_anchors(r, start, end, r.layout):
            v = parse_vmt(r, addr)
            if v:
                vmts[v.addr] = v
    return vmts, typeinfos


# ------------------------------------------------------------ string literals

#: The refcount every compiler-emitted string constant carries.
STRING_REFCOUNT = 0xFFFFFFFF

#: Longest literal accepted, in characters. Delphi embeds whole HTML templates
#: and SQL statements in the code section, so the cap is generous; it exists
#: only to keep a length read out of unrelated bytes from claiming the rest of
#: the section.
MAX_STRING_LENGTH = 0x10000

#: The control characters a string constant plausibly contains.
STRING_CONTROLS = (0x09, 0x0A, 0x0D)

#: UnicodeString's code page. It is fixed, so it and a two-byte element size
#: imply each other.
CP_UTF16 = 1200


class StringLiteral(object):
    """One string constant the compiler emitted into the code section.

    Two header shapes carry these. Through Delphi 2007 the header is a
    refcount and a length; from Delphi 2009 a code page and an element size
    precede those two, `length` counts characters rather than bytes, and the
    terminator is one element wide. `addr` is the first header byte of
    whichever shape this record has, so the record runs [addr, end).
    """

    __slots__ = ("addr", "length", "raw", "header_size", "elem_size",
                 "code_page")

    def __init__(self, addr, length, raw, header_size=8, elem_size=1,
                 code_page=None):
        self.addr = addr                  # the first header byte
        self.length = length              # characters, not bytes
        self.raw = raw                    # characters, without the terminator
        self.header_size = header_size
        self.elem_size = elem_size
        self.code_page = code_page        # None where the header has no field

    @property
    def body(self):
        """The first character: the address the compiler references."""
        return self.addr + self.header_size

    @property
    def end(self):
        """One past the terminator."""
        return self.body + (self.length + 1) * self.elem_size

    @property
    def text(self):
        if self.elem_size == 2:
            return self.raw.decode("utf-16-le")
        return self.raw.decode("latin-1")

    @property
    def kind(self):
        """The Delphi type of this constant.

        The element size is the discriminator the RTL itself uses; the code
        page distinguishes the one-byte types from each other and is left on
        the record for callers that want it.
        """
        return "UnicodeString" if self.elem_size == 2 else "AnsiString"

    def __repr__(self):
        return "<%s %08x %r>" % (self.kind, self.addr, self.text[:32])


def is_string_text(raw):
    """Printable Latin-1, tab, newline and carriage return only.

    The header alone is nearly self-checking, but "nearly" is not enough when
    a false positive declares instructions to be data. Requiring the body to
    read as text costs the handful of literals holding a binary file magic and
    buys rejection of every run of code bytes that happens to sit behind four
    0xFF bytes and a plausible length.
    """
    return all(c >= 0x20 or c in STRING_CONTROLS for c in raw)


def is_wide_string_text(raw):
    """The same predicate over UTF-16LE code points.

    Decoding is itself a check: a body holding a lone surrogate is not text,
    and rejecting it costs nothing.
    """
    try:
        text = raw.decode("utf-16-le")
    except (UnicodeDecodeError, ValueError):
        return False
    return all(ord(c) >= 0x20 or ord(c) in STRING_CONTROLS for c in text)


def parse_strrec(r, addr, limit=None):
    """Parse the Delphi 2009 string constant anchored on the refcount at `addr`.

    A code page and an element size sit in front of the refcount, so the record
    starts four bytes before the anchor.  Everything after the length is scaled
    by the element size: the body is `length` elements and the terminator is
    one more.  Element size and code page have to agree -- a two-byte element
    is a UnicodeString and its code page is 1200, and nothing else is -- which
    is what keeps a pre-2009 record whose two preceding bytes happen to read
    `01 00` from parsing as this shape.
    """
    if r.u32(addr) != STRING_REFCOUNT:
        return None
    code_page, elem = r.u16(addr - 4), r.u16(addr - 2)
    if elem not in (1, 2) or code_page is None:
        return None
    if (code_page == CP_UTF16) != (elem == 2):
        return None
    length = r.u32(addr + 4)
    if length is None or not (1 <= length <= MAX_STRING_LENGTH):
        return None
    size = (length + 1) * elem
    if limit is not None and addr + 8 + size > limit:
        return None
    raw = r.bytes(addr + 8, size)
    if len(raw) != size or any(raw[length * elem:]):
        return None
    body = bytes(raw[:length * elem])
    if not (is_wide_string_text(body) if elem == 2 else is_string_text(body)):
        return None
    return StringLiteral(addr - 4, length, body, 12, elem, code_page)


def parse_ansistring(r, addr, limit=None):
    """Parse the pre-2009 AnsiString constant whose header begins at `addr`.

    The layout is a refcount of -1, a 32-bit length, that many characters and
    a NUL terminator.  All three header facts are required: the refcount is
    exact, the length must be in range and leave the whole literal inside
    `limit`, and the byte the length points at must be the terminator.
    """
    if r.u32(addr) != STRING_REFCOUNT:
        return None
    length = r.u32(addr + 4)
    if length is None or not (1 <= length <= MAX_STRING_LENGTH):
        return None
    if limit is not None and addr + 9 + length > limit:
        return None
    raw = r.bytes(addr + 8, length)
    if len(raw) != length or not is_string_text(raw):
        return None
    if r.u8(addr + 8 + length) != 0:
        return None
    return StringLiteral(addr, length, bytes(raw))


def parse_string(r, addr, limit=None):
    """Parse the string constant anchored on the refcount dword at `addr`.

    Both header shapes are tried and the record decides which one it is, so no
    compiler version has to be guessed -- which matters, because version
    detection abstains on a quarter of binaries and being wrong either way
    costs every literal in the file.

    The 12-byte shape goes first because the shapes are not symmetric.  The
    8-byte parse of a one-character UnicodeString succeeds by coincidence --
    the character's zero high byte reads as the terminator -- yielding the
    right text with the wrong type and a span two bytes short, so trying the
    8-byte shape first would keep mis-typing exactly those records.  The
    reverse accident does not happen: the 12-byte parse accepts nothing in any
    pre-2009 binary of the corpus, and its element size and code page have to
    corroborate each other.
    """
    return parse_strrec(r, addr, limit) or parse_ansistring(r, addr, limit)


def scan_strings(r, start, end, align=4):
    """Yield every string constant in [start, end), in ascending order.

    The refcount is the anchor, and both header shapes hang off it, so one
    scan finds the candidates for both. The compiler emits these records dword
    aligned, which makes it one aligned word compare per four bytes to find
    every candidate, and `parse_string` decides which candidates are real.
    Blocks are pulled out and walked as machine arrays for the same reason
    `self_pointers` does it: asking the reader per address costs more than the
    comparison.
    """
    first = start + -start % align
    block = max(_CHUNK, align)
    for base in range(first, end, block):
        stop = min(base + block, end)
        data = r.bytes(base, stop - base)
        if len(data) == stop - base and align == 4:
            count = len(data) // 4
            words = memoryview(data)[:4 * count].cast("I")
            addrs = [base + 4 * i for i, word in enumerate(words)
                     if word == STRING_REFCOUNT]
        else:
            addrs = range(base, stop, align)
        for addr in addrs:
            literal = parse_string(r, addr, end)
            if literal is not None:
                yield literal


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
