"""Turn parsed Delphi metadata into Binary Ninja types, symbols and names."""

import bisect
import json
import re
from collections import OrderedDict

import binaryninja as bn
from binaryninja import (BinaryView, Symbol, SymbolType, Type,
                         StructureBuilder, BaseStructure,
                         NamedTypeReferenceClass)

from . import dfm
from . import messages
from . import parser as P
from . import sinks

TAG = "delphinja"
_BAD_CHARS = re.compile(r"[^A-Za-z0-9_.$]")


def setting(key, default=True):
    """A `delphinja.<key>` boolean, for a capability that has its own switch.

    Settings are registered by the plugin's __init__, which is not imported
    when this module is driven headless from the tools, so an unregistered key
    is not an error -- it is a caller who never had a UI to set it in.
    """
    try:
        return bn.Settings().get_bool("delphinja." + key)
    except Exception:
        return default


#: How much of a literal's text goes into its data variable's name.
STRING_NAME_CHARS = 24


def string_var_name(literal):
    """A readable, address-free name for a string constant.

    The text is what a reader is looking for, so it goes in the name; two
    literals holding the same words share a name, which is what the binary
    itself says about them.  Text that survives sanitizing as nothing but
    separators names itself by address instead.  The Delphi type leads, so the
    name says which of the two string types the constant is.
    """
    label = sanitize(literal.text[:STRING_NAME_CHARS].strip(), "")
    if not label.strip("_."):
        label = "%x" % literal.addr
    return literal.kind + "_" + label


# A short tag per managed type kind, for naming a field the binary gives no
# name to. The Pascal type it stands for is on the VMT's comment; the tag is
# only there so that two managed fields of one class read differently in the
# struct and so that the kind is visible where the type is a bare pointer.
_MANAGED_TAGS = {10: "LStr", 11: "WStr", 12: "Var", 13: "Arr", 14: "Rec",
                 15: "Intf", 17: "DynArr", 18: "UStr", 22: "MRec"}


def managed_field_name(field):
    """A name for a managed field, which the metadata never names.

    vmtInitTable lists what the compiler has to finalise and where, and
    nothing else: no names, because the RTL walking this table at destruction
    time has no use for one.  So the offset -- the one thing that is certainly
    unique within the class -- names the field, and the kind tag says what it
    is: `f1C_UStr`, `f20_Intf`.
    """
    return "f%X_%s" % (field["offset"],
                       _MANAGED_TAGS.get(field["kind"], "Managed"))


def sanitize(name, fallback="anon"):
    """Delphi emits compiler-generated names like '.74' for anonymous types."""
    if not name:
        return fallback
    out = _BAD_CHARS.sub("_", name)
    if out[0].isdigit() or out[0] == ".":
        out = fallback + "_" + out.lstrip(".")
    return out


# ------------------------------------------------------------------ analysis

class DelphiMetadata(object):
    """Scan results plus everything derived from them."""

    # Keep enough adjacent blocks hot for the scanners and the records they
    # immediately parse, without retaining a second copy of every executable
    # section for the lifetime of the metadata object.
    READ_CHUNK = 0x10000
    READ_CACHE_CHUNKS = 8

    def __init__(self, bv):
        self.bv = bv
        self._code_ranges = [
            (s.start, s.end) for s in bv.sections.values()
            if s.semantics in (bn.SectionSemantics.ReadOnlyCodeSectionSemantics,
                               bn.SectionSemantics.DefaultSectionSemantics)]
        # Scanner blocks are cached lazily.  Eagerly copying complete code
        # sections made even the workflow eligibility probe retain an
        # image-sized duplicate, although that probe reads only a bounded
        # prefix.  An LRU keeps the hot scanner block and nearby record reads
        # fast while placing a fixed ceiling on retained bytes.
        self._cache = OrderedDict()
        self.reader = P.Reader(
            self._read,
            lambda a: a is not None and bv.is_valid_offset(a),
            lambda a: a is not None and self._is_code(a),
            bv.address_size)
        # Which Delphi dialect this binary uses. A hardcoded 76-byte VMT
        # header is right only for Delphi 3 through 2007; 2009 onwards use 88
        # even on 32-bit, so assuming it makes the scanner silently blind to
        # every modern binary.
        layout, self.layout_score = P.detect_layout(
            self.reader, self._code_ranges,
            ptr_sizes=(bv.address_size,) if bv.address_size in (4, 8) else (4,))
        if layout is not None:
            self.reader.layout = layout
        self.layout = self.reader.layout
        self.vmts = {}
        self.typeinfos = {}
        self.strings = {}
        self.char_arrays = {}
        self._children = None
        self._interfaces = None
        self._uregions = None
        self._uevidence = None
        self._class_ti = None

    def _read(self, addr, length):
        if length <= 0:
            return b""
        containing = next(((start, end) for start, end in self._code_ranges
                           if start <= addr and addr + length <= end), None)
        out = bytearray()
        pos = addr
        stop = addr + length
        while pos < stop:
            if containing is None:
                want = min(self.READ_CHUNK, stop - pos)
                try:
                    data = self.bv.read(pos, want)
                except Exception:
                    data = b""
            else:
                section_start, section_end = containing
                index = (pos - section_start) // self.READ_CHUNK
                base = section_start + index * self.READ_CHUNK
                key = (section_start, index)
                data = self._cache.pop(key, None)
                if data is None:
                    want = min(self.READ_CHUNK, section_end - base)
                    try:
                        data = self.bv.read(base, want)
                    except Exception:
                        data = b""
                self._cache[key] = data
                while len(self._cache) > self.READ_CACHE_CHUNKS:
                    self._cache.popitem(last=False)
                offset = pos - base
                want = min(stop - pos, len(data) - offset)
                data = data[offset:offset + max(0, want)]
            out += data
            pos += len(data)
            if not data or len(data) < want:
                break
        return bytes(out)

    def _is_code(self, addr):
        return any(s <= addr < e for s, e in self._code_ranges)

    # -- scanning ---------------------------------------------------------

    def scan(self, ranges=None, progress=None):
        if ranges is None:
            ranges = self._code_ranges or [(self.bv.start, self.bv.end)]
        for start, end in ranges:
            v, t = P.scan(self.reader, start, end, progress)
            self.vmts.update(v)
            self.typeinfos.update(t)
            for literal in P.scan_strings(self.reader, start, end):
                self.strings[literal.addr] = literal
            self._children = None
            self._interfaces = None
            self._uregions = None
            self._uevidence = None
            self._class_ti = None
        self._scan_char_arrays(ranges)
        return self

    def _scan_char_arrays(self, ranges):
        """Recover the constants that carry no header, after everything that
        does.

        Order is the whole point: a header-less run is accepted only where no
        record already accounts for the bytes, so every VMT, TTypeInfo and
        header-validated literal has to be known first.  That also means this
        cannot run per range like the rest of the scan -- a record found in
        one section still rules a run in another out.

        References are looked for across the whole image rather than the code
        sections alone.  A PChar constant reached through an initialised
        pointer in .data is referenced by exactly one dword and that dword is
        not in the code, and on the corpus restricting the search to
        executable ranges lost 47 of 75 in ImageWriterSvc and 55 of 83 in
        DX.HttpDiag -- all of them genuine.
        """
        claimed = [(s, e) for s, e, _ in self.spans()]
        image = [(s.start, s.end) for s in self.bv.sections.values()]
        for literal in P.scan_headerless_strings(
                self.reader, ranges, claimed, ref_ranges=image or ranges):
            self.char_arrays[literal.addr] = literal

    # -- derived views ----------------------------------------------------

    def spans(self, strings=True):
        """Every (start, end, label) byte range that metadata occupies.

        String constants are metadata in the sense that matters here: they sit
        in the code section, they are not instructions, and a function
        overlapping one is bogus.  `strings=False` restricts the answer to the
        RTTI records, which is what unit inference reasons about.
        """
        out = []
        for ti in self.typeinfos.values():
            start = ti.ptr_addr if ti.ptr_addr is not None else ti.addr
            out.append((start, ti.end, "TypeInfo %s" % ti.name))
        for v in self.vmts.values():
            out.append((v.header, v.vtable_end, "VMT %s" % v.name))
            for s, e, label in v.regions:
                out.append((s, e, "%s %s" % (label, v.name)))
        if strings:
            for literal in self.strings.values():
                out.append((literal.addr, literal.end, literal.kind))
            for literal in self.char_arrays.values():
                out.append((literal.addr, literal.end, literal.kind))
        return sorted(out)

    def regions(self, gap=0x40, strings=True):
        """Coalesced metadata regions, the answer to 'where else is this?'."""
        return P.cluster([(s, e) for s, e, _ in self.spans(strings)], gap)

    def typeinfo_by_ptr(self, pptypeinfo):
        """PPTypeInfo cell -> parsed TypeInfo."""
        if not pptypeinfo or not self.bv.is_valid_offset(pptypeinfo):
            return None
        return self.typeinfo_at(self.reader.u32(pptypeinfo))

    def typeinfo_at(self, addr):
        """TTypeInfo record address -> parsed TypeInfo.

        The scan finds a record only where the compiler put a PPTypeInfo cell
        in front of it, and the ones the init tables name have no such cell,
        so falling back to parsing on demand is what makes those reachable at
        all rather than an optimisation.
        """
        if not addr:
            return None
        ti = self.typeinfos.get(addr)
        return ti if ti is not None else P.parse_typeinfo(self.reader, addr)

    UNIT_REGION_GAP = 0x80

    def unit_for(self, record):
        """(unit, source) for a VMT or TypeInfo. source is 'rtti' or 'nearby'.

        Only classes compiled with $M+ (everything descended from TPersistent)
        carry a tkClass record, and the UnitName lives in that record -- so
        TReader, TList and TStream have a VMT and a class name but no unit.
        The linker emits each unit's metadata contiguously, so when every
        RTTI record sharing a metadata region names the same unit, a class in
        that region belongs to it too.  Regions with mixed or no evidence
        return None rather than a guess.
        """
        unit = getattr(record, "unit", None)
        if unit is None:
            owner = self.class_typeinfo(record)      # a VMT carries no unit
            unit = owner.unit if owner else None
        if unit:
            return unit, "rtti"
        addr = getattr(record, "header", None)
        if addr is None:
            addr = record.addr
        for start, end in self._unit_regions():
            if start <= addr < end:
                units = self._unit_evidence().get((start, end))
                if units and len(units) == 1:
                    return next(iter(units)), "nearby"
                return None, None
        return None, None

    def class_typeinfo(self, vmt):
        """The tkClass record describing this VMT, if the class has one."""
        if self._class_ti is None:
            self._class_ti = {}
            for ti in self.typeinfos.values():
                if ti.kind == 7 and ti.data.get("ClassType"):
                    self._class_ti.setdefault(ti.data["ClassType"], ti)
        return self._class_ti.get(getattr(vmt, "addr", None))

    def _unit_regions(self):
        """The RTTI regions only.

        A string constant declares no unit, and the compiler emits literals
        between the tables, so counting them here would bridge two units'
        metadata into one region and turn single-unit evidence into mixed.
        """
        if self._uregions is None:
            self._uregions = self.regions(self.UNIT_REGION_GAP, strings=False)
        return self._uregions

    def _unit_evidence(self):
        """Region -> the set of unit names any RTTI record in it declares."""
        if self._uevidence is None:
            self._uevidence = {}
            points = [(ti.addr, ti.unit) for ti in self.typeinfos.values()
                      if ti.unit]
            for start, end in self._unit_regions():
                self._uevidence[(start, end)] = {
                    u for a, u in points if start <= a < end}
        return self._uevidence

    def qualified(self, record):
        """'Classes_TReader' when the unit is known, else 'TReader'."""
        name = sanitize(record.name)
        unit, _ = self.unit_for(record)
        return "%s_%s" % (sanitize(unit), name) if unit else name

    def interface_names(self):
        """GUID string -> interface name, from the tkInterface records."""
        if self._interfaces is None:
            self._interfaces = {}
            for ti in self.typeinfos.values():
                guid = ti.data.get("GUID") if ti.kind == 15 else None
                if guid:
                    self._interfaces.setdefault(guid, ti.name)
        return self._interfaces

    def children(self):
        """Parent VMT address -> the VMTs that derive from it."""
        if self._children is None:
            self._children = {}
            for v in self.vmts.values():
                if v.parent:
                    self._children.setdefault(v.parent, []).append(v)
        return self._children

    def hierarchy(self, vmt):
        """vmt, all of its ancestors, and all of its descendants.

        A virtual property accessor is published on one class but the slot it
        names is shared by the whole branch: the ancestor that introduced it
        and every descendant, overriding or not.
        """
        out = list(self.class_chain(vmt))
        stack = [vmt]
        seen = {v.addr for v in out}
        while stack:
            cur = stack.pop()
            for child in self.children().get(cur.addr, []):
                if child.addr not in seen:
                    seen.add(child.addr)
                    out.append(child)
                    stack.append(child)
        return out

    def class_chain(self, vmt):
        """vmt and every ancestor, root first."""
        chain, seen = [], set()
        cur = vmt
        while cur is not None and cur.addr not in seen:
            seen.add(cur.addr)
            chain.append(cur)
            cur = self.vmts.get(cur.parent) if cur.parent else None
        chain.reverse()
        return chain


# ---------------------------------------------------------------- undefining

def _range_index(ranges):
    """Prepare `ranges` for O(log n) overlap queries by `_overlaps`.

    Returns the range starts in ascending order alongside a running maximum
    of the ends, so that the ranges beginning before any given address are a
    prefix of the array and the furthest either of them reaches is one lookup.

    The ranges are indexed, never coalesced.  Merging even two spans that
    merely touch answers differently for a zero-length query on the seam --
    [0,10) and [10,20) reject a query of [10,10), their merger accepts it --
    and merging across any gap claims bytes no caller passed, which undefines
    functions that are not metadata.
    """
    ordered = sorted(ranges)
    starts = [s for s, _ in ordered]
    reach, furthest = [], None
    for _, end in ordered:
        if furthest is None or end > furthest:
            furthest = end
        reach.append(furthest)
    return starts, reach


def _overlaps(index, lo, hi):
    """Does [lo, hi) overlap any indexed range, exactly as `lo < end and
    hi > start` scanned over all of them would decide?

    The ranges with `start < hi` are `starts[:k]`, and one of them satisfies
    `end > lo` precisely when the largest end among them does.
    """
    starts, reach = index
    k = bisect.bisect_left(starts, hi)
    return k > 0 and reach[k - 1] > lo


def undefine_functions(bv, ranges, log=None):
    """Remove every automatic function that overlaps any of `ranges`.

    Linear sweep happily disassembles RTTI, so these tables usually carry a
    handful of large bogus functions that poison xrefs and the call graph.
    User-created functions are explicit analyst state and are left alone.
    """
    # Testing every function against every span is quadratic, and a binary
    # with 23,000 functions over 6,000 metadata spans spends more time here
    # than in the rest of the plugin put together. Index the spans once.
    index = _range_index(ranges)
    victims = []
    for f in list(bv.functions):
        # Test the blocks the function actually covers, not start..highest:
        # a real function with a far outlined tail can span a metadata region
        # it never touches, and removing that would be a real loss.
        try:
            covered = [(r.start, r.end) for r in f.address_ranges]
        except Exception:
            covered = [(b.start, b.end) for b in f.basic_blocks]
        # A user function is an explicit assertion and is never ours to
        # discard.  The workflow cleanup exists only to undo linear sweep's
        # automatically discovered functions over metadata.
        if f.auto and any(_overlaps(index, lo, hi) for lo, hi in covered):
            victims.append(f)
    for f in victims:
        if log:
            log("undefining %s at 0x%x (%d blocks)"
                % (f.name, f.start, len(f.basic_blocks)))
        bv.remove_function(f)
    return victims


# -------------------------------------------------------------- type mapping

_ORD_WIDTH = {"otSByte": (1, True), "otUByte": (1, False),
              "otSWord": (2, True), "otUWord": (2, False),
              "otSLong": (4, True), "otULong": (4, False)}


class TypeFactory(object):
    """Builds Binary Ninja types out of RTTI records, memoised by name."""

    def __init__(self, md, prefix="", sink=None):
        self.md = md
        self.bv = md.bv
        self.sink = sink or sinks.ViewSink(md.bv, md)
        self.prefix = prefix
        self.defined = {}
        self.owned = {}
        self.enums = 0
        self.structs = 0
        self.inline_refused = []         # (vmt, managed field) left unplaced
        self._register_cc = False        # unresolved; None once looked up

    def qname(self, name):
        return self.prefix + sanitize(name)

    # -- enumerations -----------------------------------------------------

    def enum_type(self, ti):
        name = self.qname(ti.name)
        width, signed = _ORD_WIDTH.get(ti.data.get("OrdType"), (1, False))
        if name not in self.defined:
            lo = ti.data.get("MinValue") or 0
            members = [(sanitize(n), lo + i)
                       for i, n in enumerate(ti.data.get("Names") or [])]
            if not members:
                return Type.int(width, signed)
            self.sink.add_type(
                name, Type.enumeration(self.bv.arch, members, width=width,
                                       sign=signed))
            self.defined[name] = True
            self.enums += 1
        return Type.named_type_reference(
            NamedTypeReferenceClass.EnumNamedTypeClass, name, width=width)

    # -- classes ----------------------------------------------------------

    def class_type(self, vmt, class_props):
        """Define a struct for `vmt`, deriving from its parent's struct."""
        name = self.qname(vmt.name)
        if name in self.defined:
            return name
        self.defined[name] = True          # set first: guards parent cycles

        parent_vmt = self.md.vmts.get(vmt.parent) if vmt.parent else None
        parent_name = None
        parent_size = 0
        if parent_vmt is not None and parent_vmt.addr != vmt.addr:
            parent_name = self.class_type(parent_vmt, class_props)
            parent_size = parent_vmt.instance_size or 0

        sb = StructureBuilder.create()
        sb.packed = True
        sb.width = vmt.instance_size or max(parent_size, 4)
        if parent_name:
            sb.base_structures = [BaseStructure(
                Type.named_type_reference(
                    NamedTypeReferenceClass.StructNamedTypeClass, parent_name),
                0, parent_size)]
        else:
            sb.add_member_at_offset("__vmt", Type.pointer(self.bv.arch,
                                                          Type.void()), 0)

        for offset, (mname, mtype) in sorted(self.owned.get(vmt.addr, {}).items()):
            if offset < parent_size or offset >= sb.width:
                continue
            try:
                sb.add_member_at_offset(mname, mtype, offset)
            except Exception:
                pass

        self.sink.add_type(name, Type.structure_type(sb))
        self.structs += 1
        return name

    def assign_members(self, class_props):
        """Work out which class in each hierarchy actually declares a field.

        Delphi publishes a property on the descendant that exposes it, not on
        the ancestor that stores it -- TEdit publishes BorderStyle even though
        the field lives inside TCustomEdit's part of the instance.  Placing
        the member on the publisher would collide with the base structure, so
        each offset is handed to the ancestor whose own slice of the instance
        contains it.
        """
        self.owned = {}
        self.inline_refused = []
        for vmt in self.md.vmts.values():
            chain = self.md.class_chain(vmt)           # root first
            for offset, mname, mtype in self._members(vmt, class_props):
                owner = None
                prev = 0
                for cls in chain:
                    size = cls.instance_size or 0
                    if prev <= offset < size:
                        owner = cls
                        break
                    prev = size
                if owner is None:
                    owner = vmt
                self.owned.setdefault(owner.addr, {}).setdefault(
                    offset, (mname, mtype))

    def _members(self, vmt, class_props):
        """Published fields, the fields published properties read, and the
        managed fields vmtInitTable lists.

        The three sources describe disjoint parts of the instance and none of
        them is complete on its own.  The published field table carries only
        class-typed fields -- the components dropped on a form -- and the
        property accessors reach whatever a published property happens to read
        directly.  Everything managed is in neither: a `string`, an interface
        reference, a dynamic array or a Variant field is invisible to both,
        which is every such member of every class.
        """
        seen = {}
        for f in vmt.fields:
            cls = None
            if f["class_index"] < len(vmt.field_classes):
                pcls = vmt.field_classes[f["class_index"]]
                cls = self.md.vmts.get(self.md.reader.u32(pcls) if pcls else None)
            ftype = (Type.pointer(self.bv.arch, Type.named_type_reference(
                NamedTypeReferenceClass.StructNamedTypeClass,
                self.qname(cls.name))) if cls
                else Type.pointer(self.bv.arch, Type.void()))
            seen[f["offset"]] = (sanitize(f["name"]), ftype)

        for prop in class_props.get(vmt.addr, []):
            for accessor in ("GetProc", "SetProc"):
                kind, value = P.decode_accessor(prop[accessor])
                if kind != "field" or value in seen:
                    continue
                seen[value] = ("F" + sanitize(prop["Name"]),
                               self.prop_type(prop))

        # Managed fields last, so a real backing-field name already found for
        # an offset by either source above wins over a synthesised one: the
        # init table carries no names at all, only types and offsets.
        for f in vmt.managed:
            if f["offset"] in seen:
                continue
            if f["inline"]:
                # An inline record or array occupies as many bytes as its own
                # type does, and this table does not say how many. Placing a
                # member of a guessed width would overlap the field after it,
                # so say so and place nothing.
                self.inline_refused.append((vmt, f))
                continue
            # The record's own address: the parser has already followed
            # whatever indirection this era's TypeRef carries.
            ti = self.md.typeinfo_at(f["typeinfo"])
            seen[f["offset"]] = (managed_field_name(f), self.rtti_type(ti))
        return sorted((off, n, t) for off, (n, t) in seen.items())

    # -- RTTI kind -> BN type ---------------------------------------------

    def method_type(self):
        """TMethod: every Delphi event property is one of these."""
        name = self.prefix + "TMethod"
        if name not in self.defined:
            sb = StructureBuilder.create()
            sb.packed = True
            ptr = Type.pointer(self.bv.arch, Type.void())
            sb.add_member_at_offset("Code", ptr, 0)
            sb.add_member_at_offset("Data", ptr, 4)
            sb.width = 8
            self.sink.add_type(name, Type.structure_type(sb))
            self.defined[name] = True
            self.structs += 1
        return Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, name, width=8)

    # -- the tables that reach code -------------------------------------

    def code_pointer(self):
        """A pointer to a function, not to void.

        The distinction is the whole point of typing these tables: a slot
        declared as a function pointer makes the address it holds a reference
        to that code, so the handler stops looking unreachable.  Delphi's own
        convention comes with it -- Self arrives in EAX for every one of these
        entries.
        """
        return Type.pointer(self.bv.arch,
                            Type.function(calling_convention=self._cc()))

    def _cc(self):
        if self._register_cc is False:
            try:
                self._register_cc = self.bv.arch.calling_conventions.get(
                    "register")
            except Exception:
                self._register_cc = None
        return self._register_cc

    def dynamic_table_type(self, count):
        """The dynamic method table: parallel id and handler arrays.

        Delphi's dynamic (and message) methods are dispatched by searching
        this table, so nothing in the code ever names the handlers -- they are
        reachable only as elements of the pointer array, and only if something
        says that is what the bytes are.
        """
        name = "%sTDynamicMethodTable_%d" % (self.prefix, count)
        width = 2 + 6 * count
        if name not in self.defined:
            sb = StructureBuilder.create()
            sb.packed = True
            sb.add_member_at_offset("Count", Type.int(2, False), 0)
            sb.add_member_at_offset("Ids", Type.array(Type.int(2, True),
                                                      count), 2)
            sb.add_member_at_offset(
                "Handlers", Type.array(self.code_pointer(), count), 2 + 2 * count)
            sb.width = width
            self.sink.add_type(name, Type.structure_type(sb))
            self.defined[name] = True
            self.structs += 1
        return Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, name, width=width)

    def code_pointer_array(self, count):
        """A method table: `count` consecutive pointers to code."""
        return Type.array(self.code_pointer(), count)

    def string_literal_type(self, literal):
        """A compiler-emitted string constant, header to terminator.

        The record is the whole literal -- header, characters and terminator
        -- so one data variable of this type covers every byte the compiler
        reserved, and nothing is left over for the sweep to read as code.  The
        character array carries the terminator, which is what makes it a C
        string the UI renders as text.

        Three shapes exist and each gets its own name, because the length
        alone no longer fixes the width: `TAnsiStringLiteral_N` is the 8-byte
        header, `TAnsiStringLiteral12_N` the 12-byte one Delphi 2009 gave the
        same type, and `TUnicodeStringLiteral_N` the 12-byte header over
        two-byte characters.
        """
        length, elem = literal.length, literal.elem_size
        header = literal.header_size
        suffix = "12" if header == 12 and elem == 1 else ""
        name = "%sT%sLiteral%s_%d" % (self.prefix, literal.kind, suffix, length)
        width = header + (length + 1) * elem
        if name not in self.defined:
            sb = StructureBuilder.create()
            sb.packed = True
            if header == 12:
                sb.add_member_at_offset("CodePage", Type.int(2, False), 0)
                sb.add_member_at_offset("ElemSize", Type.int(2, False), 2)
            sb.add_member_at_offset("RefCount", Type.int(4, True), header - 8)
            sb.add_member_at_offset("Length", Type.int(4, True), header - 4)
            char = Type.wide_char(2) if elem == 2 else Type.char()
            sb.add_member_at_offset("Data", Type.array(char, length + 1), header)
            sb.width = width
            self.sink.add_type(name, Type.structure_type(sb))
            self.defined[name] = True
            self.structs += 1
        return Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, name, width=width)

    def char_array_type(self, literal):
        """A header-less constant: the characters and the terminator, and
        nothing else.

        No struct and no named type, unlike `string_literal_type`, because
        there is no record here to name.  A `PChar` constant is exactly
        `array[0..n] of AnsiChar` in the image -- no refcount, no length, no
        code page -- so a char array of n+1 elements describes every byte the
        compiler reserved and asserts nothing about the bytes in front of it,
        which belong to whatever the compiler emitted before.  Wrapping it in
        a `TPCharLiteral_N` struct with the header fields left out would only
        put a name on an array.
        """
        char = Type.wide_char(2) if literal.elem_size == 2 else Type.char()
        return Type.array(char, literal.length + 1)

    INTF_ENTRY_SIZE = 28

    def _interface_entry_type(self):
        """TInterfaceEntry: GUID, vtable, instance offset, getter."""
        name = self.prefix + "TInterfaceEntry"
        if name not in self.defined:
            sb = StructureBuilder.create()
            sb.packed = True
            sb.add_member_at_offset("IID", Type.array(Type.int(1, False), 16), 0)
            sb.add_member_at_offset(
                "VTable", Type.pointer(self.bv.arch, self.code_pointer()), 16)
            sb.add_member_at_offset("IOffset", Type.int(4, True), 20)
            # Usually zero, and sometimes tagged ($FF/$FE) rather than an
            # address; a tagged value is not a valid offset, so no reference
            # comes of it.
            sb.add_member_at_offset("ImplGetter", self.code_pointer(), 24)
            sb.width = self.INTF_ENTRY_SIZE
            self.sink.add_type(name, Type.structure_type(sb))
            self.defined[name] = True
            self.structs += 1
        return Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, name,
            width=self.INTF_ENTRY_SIZE)

    def interface_table_type(self, count):
        """TInterfaceTable: the count, then one entry per implemented interface.

        Typing it is what makes each interface's vtable a referenced address
        rather than a dword that happens to look like one.
        """
        entry = self._interface_entry_type()
        name = "%sTInterfaceTable_%d" % (self.prefix, count)
        width = 4 + self.INTF_ENTRY_SIZE * count
        if name not in self.defined:
            sb = StructureBuilder.create()
            sb.packed = True
            sb.add_member_at_offset("EntryCount", Type.int(4, True), 0)
            sb.add_member_at_offset("Entries", Type.array(entry, count), 4)
            sb.width = width
            self.sink.add_type(name, Type.structure_type(sb))
            self.defined[name] = True
            self.structs += 1
        return Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, name, width=width)

    def prop_type(self, prop):
        return self.rtti_type(self.md.typeinfo_by_ptr(prop["PropType"]))

    def rtti_type(self, ti, seen=frozenset()):
        arch = self.bv.arch
        if ti is None:
            return Type.int(4)
        k = ti.kind
        if k in (1,):                                    # tkInteger
            w, s = _ORD_WIDTH.get(ti.data.get("OrdType"), (4, True))
            return Type.int(w, s)
        if k == 2:
            return Type.char()
        if k == 9:
            return Type.wide_char(2)
        if k == 3:
            return self.enum_type(ti)
        if k == 4:
            ft = ti.data.get("FloatType")
            return {"ftSingle": Type.float(4), "ftDouble": Type.float(8),
                    "ftExtended": Type.float(10), "ftComp": Type.int(8),
                    "ftCurr": Type.int(8)}.get(ft, Type.float(8))
        if k == 5:                                       # ShortString
            return Type.array(Type.char(), (ti.data.get("MaxLength") or 255) + 1)
        if k == 6:                                       # set of ordinal
            w, _ = _ORD_WIDTH.get(ti.data.get("OrdType"), (1, False))
            return Type.int(w, False)
        if k == 7:                                       # class reference
            cls = self.md.vmts.get(ti.data.get("ClassType"))
            if cls is not None:
                return Type.pointer(arch, Type.named_type_reference(
                    NamedTypeReferenceClass.StructNamedTypeClass,
                    self.qname(cls.name)))
            return Type.pointer(arch, Type.void())
        if k == 8:                                       # method pointer
            return self.method_type()
        if k in (10, 11):                                # long / wide string
            return Type.pointer(arch, Type.char() if k == 10
                                else Type.wide_char(2))
        if k == 12:
            return Type.array(Type.int(1, False), 16)    # TVarData
        if k == 16:
            return Type.int(8)
        if k == 18:                                      # UnicodeString
            # Two bytes per character, and the compiler passes the address of
            # the first one.  Typing it `char *` -- the obvious mistake, and
            # the one that makes every recovered string in a modern binary
            # decompile as its first letter -- is wrong about the element,
            # not just about the encoding.
            return Type.pointer(arch, Type.wide_char(2))
        if k in (13, 14, 22):                     # array / record / mrecord
            size = ti.data.get("Size") or 4
            return Type.array(Type.int(1, False), max(1, size))
        if k == 20:                                      # typed pointer
            # `Pointer` itself publishes no RefType, and a type that points at
            # itself -- a linked-list node -- would otherwise recurse forever,
            # so an unresolved or repeated target is void.
            target = self.md.typeinfo_by_ptr(ti.data.get("RefType"))
            if target is None or target.addr in seen:
                return Type.pointer(arch, Type.void())
            return Type.pointer(arch, self.rtti_type(target,
                                                     seen | {ti.addr}))
        if k in (15, 17, 19, 21):
            # An interface is a pointer to its own vtable, a dynamic array a
            # pointer to its first element, a class reference a pointer to a
            # VMT and a procedure type a code address.  All four are one
            # pointer wide and none of them has a struct here to point at.
            return Type.pointer(arch, Type.void())
        return Type.int(4)


# ------------------------------------------------------------- name claiming

class NameClaims(object):
    """Resolves which class owns a shared code address.

    A VMT slot holds the same address in every descendant that does not
    override it, so an address seen in ten classes belongs to whichever of
    them sits highest in the hierarchy.  Depth is the length of the class
    chain, so the shallowest claim wins; genuine ties between unrelated
    classes are dropped rather than guessed at.
    """

    def __init__(self):
        self.claims = {}
        self.conflicts = 0

    def claim(self, addr, name, depth, owner=None, register_cc=True,
              kind=P.MK_METHOD):
        """`kind` is what shape Self has, from TVmtMethodExEntry.Flags.

        Everything the extended array does not describe -- a dynamic handler,
        a property accessor, a standard TObject slot -- is an ordinary
        instance method, which is what the default says.
        """
        if not addr:
            return
        best = self.claims.get(addr)
        if best is None or depth < best[1]:
            self.claims[addr] = (name, depth, False, owner, register_cc, kind)
        elif depth == best[1] and name != best[0]:
            self.claims[addr] = best[:2] + (True,) + best[3:]

    def resolved(self):
        for addr, (name, _, tied, owner, register_cc, kind) in sorted(
                self.claims.items()):
            if tied:
                self.conflicts += 1
                continue
            yield addr, name, owner, register_cc, kind


# -------------------------------------------------------------------- applier

VMT_HEADER_TYPE = "TVmtHeader"
# How each data slot is typed, keyed by slot name rather than by position:
# which slots a header has differs per era -- Delphi 2 has neither vmtSelfPtr
# nor vmtIntfTable -- so the layout says which of these to emit and in what
# order, and a positional table would type a Delphi 2 header two slots out.
# The virtual slots that follow are appended from P.std_methods() for the same
# reason.
_VMT_SLOT_TYPES = {
    "vmtSelfPtr": "void*", "vmtIntfTable": "void*", "vmtAutoTable": "void*",
    "vmtInitTable": "void*", "vmtTypeInfo": "void*", "vmtFieldTable": "void*",
    "vmtMethodTable": "void*", "vmtDynamicTable": "void*",
    "vmtClassName": "char*", "vmtInstanceSize": "uint32",
    "vmtParent": "void*",
}


class Applier(object):
    def __init__(self, md, options=None, sink=None):
        self.md = md
        self.bv = md.bv
        self.opt = {
            "prefix": "",
            "undefine": True,
            "types": True,
            "data_vars": True,
            "comments": True,
            "rename_functions": True,
            "self_param": True,
            # Form streams live in the resource directory, so recovering them
            # is a pass over the whole file rather than over the code sections
            # the rest of this works on. Its own switch, defaulting to the
            # registered setting, so its cost and its results can be
            # attributed on their own.
            "dfm_events": setting("dfm"),
        }
        self.opt.update(options or {})
        self.sink = sink or sinks.ViewSink(md.bv, md)
        self.factory = TypeFactory(md, self.opt["prefix"], self.sink)
        self.stats = {"functions_removed": 0, "functions_named": 0,
                      "functions_created": 0, "data_vars": 0,
                      "comments": 0, "enums": 0, "structs": 0,
                      "self_typed": 0, "name_conflicts": 0, "strings": 0,
                      "char_arrays": 0,
                      "dfm_streams": 0, "dfm_events_bound": 0,
                      "dfm_events_unbound": 0}
        self.log_lines = []

    def log(self, msg):
        self.log_lines.append(msg)
        bn.log_info(msg, TAG)

    # -- top level --------------------------------------------------------

    def run(self):
        md = self.md
        self.log("%d VMTs, %d TypeInfo records, %d string constants, "
                 "%d header-less constants, %d metadata regions"
                 % (len(md.vmts), len(md.typeinfos), len(md.strings),
                    len(md.char_arrays), len(md.regions())))

        if self.opt["undefine"]:
            # Exact record spans, never the coalesced regions: the filler
            # between two records is often real code (Delphi interleaves
            # small helpers with its tables), and merging across it would
            # delete genuine functions.
            spans = [(s, e) for s, e, _ in md.spans()]
            removed = undefine_functions(self.bv, spans, self.log)
            self.stats["functions_removed"] = len(removed)

        class_props = self._class_props()
        if self.opt["types"]:
            self._define_vmt_header_type()
            self.factory.assign_members(class_props)
            for vmt, f in self.factory.inline_refused:
                self.log("%s: managed field at +0x%x is an inline %s (%s); "
                         "its width is not in the metadata, so it is left "
                         "unplaced" % (vmt.name, f["offset"], f["kind_name"],
                                       f["type_name"]))
            for vmt in md.vmts.values():
                try:
                    self.factory.class_type(vmt, class_props)
                except Exception as exc:
                    bn.log_warn("class %s: %s" % (vmt.name, exc), TAG)
            for ti in md.typeinfos.values():
                if ti.kind == 3:
                    try:
                        self.factory.enum_type(ti)
                    except Exception as exc:
                        bn.log_warn("enum %s: %s" % (ti.name, exc), TAG)

        if self.opt["data_vars"] or self.opt["comments"]:
            # Literals first: an RTTI record is the stronger evidence, so on
            # the rare address both claim, the record's declaration wins.
            for literal in md.strings.values():
                self._apply_string(literal)
            for literal in md.char_arrays.values():
                self._apply_char_array(literal)
            for ti in md.typeinfos.values():
                self._apply_typeinfo(ti)
            for vmt in md.vmts.values():
                self._apply_vmt(vmt)

        if self.opt["rename_functions"]:
            self._name_functions(class_props)
        self._finish()

        self.log("done: " + ", ".join("%s=%d" % kv
                                      for kv in sorted(self.stats.items())))
        return self.stats

    def _class_props(self):
        """VMT address -> published properties from the matching TypeInfo."""
        out = {}
        for ti in self.md.typeinfos.values():
            if ti.kind == 7 and ti.data.get("ClassType"):
                out.setdefault(ti.data["ClassType"], []).extend(ti.props)
        return out

    # -- data / symbols / comments ---------------------------------------

    def _define_vmt_header_type(self):
        name = self.opt["prefix"] + VMT_HEADER_TYPE
        sb = StructureBuilder.create()
        sb.packed = True
        layout = self.md.layout
        ptr = Type.pointer(self.bv.arch, Type.void())
        fields = ([(slot[3:], _VMT_SLOT_TYPES[slot])
                   for _, slot in P.data_slots(layout)] +
                  [(m, "code*") for _, m in P.std_methods(layout)])
        for i, (fname, kind) in enumerate(fields):
            t = (Type.int(layout.ptr_size, False) if kind == "uint32"
                 else Type.pointer(self.bv.arch, Type.char()) if kind == "char*"
                 else self.factory.code_pointer() if kind == "code*"
                 else ptr)
            sb.add_member_at_offset(fname, t, i * layout.ptr_size)
        sb.width = layout.header_size
        self.sink.add_type(name, Type.structure_type(sb))

    def _data(self, addr, ty, name):
        if not self.opt["data_vars"]:
            return
        try:
            self.sink.add_data_var(addr, ty, name)
            self.stats["data_vars"] += 1
        except Exception as exc:
            bn.log_warn("data var at 0x%x: %s" % (addr, exc), TAG)

    def _bytes_var(self, addr, end, name):
        if end > addr:
            self._data(addr, Type.array(Type.int(1, False), end - addr), name)

    def _comment(self, addr, text):
        if self.opt["comments"] and text and self.sink.supports_comments:
            if self.sink.set_comment(addr, text) is not False:
                self.stats["comments"] += 1

    def _apply_string(self, literal):
        """Declare one string constant as the record it is.

        Every byte the compiler reserved is inside the declaration, header and
        terminator included, which is what keeps the sweep from reading any of
        it as an instruction.
        """
        before = self.stats["data_vars"]
        self._data(literal.addr, self.factory.string_literal_type(literal),
                   string_var_name(literal))
        self.stats["strings"] += self.stats["data_vars"] - before

    def _apply_char_array(self, literal):
        """Declare one header-less constant as the char array it is."""
        before = self.stats["data_vars"]
        self._data(literal.addr, self.factory.char_array_type(literal),
                   string_var_name(literal))
        self.stats["char_arrays"] += self.stats["data_vars"] - before

    def _apply_typeinfo(self, ti):
        base = self.md.qualified(ti)
        if ti.ptr_addr is not None:
            self._data(ti.ptr_addr,
                       Type.pointer(self.bv.arch, Type.void()),
                       "PTypeInfo_" + base)
        self._bytes_var(ti.addr, ti.end, "TypeInfo_" + base)
        self._comment(ti.addr, describe_typeinfo(self.md, ti))

    def _apply_vmt(self, vmt):
        base = self.md.qualified(vmt)
        self._data(vmt.header, Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass,
            self.opt["prefix"] + VMT_HEADER_TYPE,
            width=self.md.layout.header_size), "VMT_" + base)
        n = len(vmt.virtuals)
        if n:
            self._data(vmt.addr, self.factory.code_pointer_array(n),
                       "vtable_" + base)
        self._comment(vmt.header, describe_vmt(self.md, vmt))
        typed = self._apply_tables(vmt, base)
        for start, end, label in vmt.regions:
            if start in typed:
                continue
            # A class emits one region per extended method entry, so the
            # label carries the method's own name to tell them apart -- and
            # that name comes out of the binary, so it goes through sanitize
            # like every other name does.
            self._bytes_var(start, end, "%s_%s" % (sanitize(label), base))

    def _apply_tables(self, vmt, base):
        """Declare the dynamic and interface method tables as what they are.

        Both are arrays of code pointers, and both are the only thing that
        reaches the code they point at: a message handler is found by scanning
        the dynamic table, and an interface method is called through the
        interface's vtable, so no instruction anywhere holds either address.
        Left as bytes -- which is what the region fallback makes them -- every
        one of those functions has no references at all, which is both wrong
        and, since it is what the core's unused-function pass tests, dangerous.

        Returns the region starts handled here, so the caller does not also
        cover them with a byte array.
        """
        handled = set()
        table = vmt.dynamic_table
        if table and table["count"]:
            self._data(table["addr"],
                       self.factory.dynamic_table_type(table["count"]),
                       "DynamicTable_" + base)
            handled.add(table["addr"])

        for entry in vmt.interfaces:
            vtable, slots = entry["vtable"], entry.get("slots") or 0
            # Two interfaces of one class can share a vtable, when the second
            # is an ancestor of the first and needs no thunks of its own.
            if not slots or vtable in handled:
                continue
            # One class implements several interfaces, so the class name alone
            # would name every one of its vtables the same thing.
            iname = sanitize(self.md.interface_names().get(entry["guid"],
                                                           "IUnknown"))
            self._data(vtable, self.factory.code_pointer_array(slots),
                       "IntfVTable_%s_%s" % (base, iname))
            handled.add(vtable)

        start = vmt.slots.get("vmtIntfTable")
        if vmt.interfaces and start:
            self._data(start,
                       self.factory.interface_table_type(len(vmt.interfaces)),
                       "IntfTable_" + base)
            handled.add(start)
        return handled

    # -- function naming --------------------------------------------------

    def _name_functions(self, class_props):
        claims = NameClaims()
        declared = self._declared_dynamic_names()
        slots = self._declared_slot_names()
        stubs = self._abstract_stubs()
        for vmt in self.md.vmts.values():
            depth = len(self.md.class_chain(vmt))
            cls = sanitize(vmt.name)
            # Both method arrays. All but a fraction of a percent of a modern
            # binary's method names live in the extended one, and where the
            # two describe the same method they agree on its name, so the
            # duplicate claims settle rather than count as a conflict.
            for m in vmt.methods + vmt.methods_ex:
                claims.claim(m["addr"], "%s.%s" % (cls, sanitize(m["name"])),
                             depth, vmt.addr,
                             kind=m.get("method_kind", P.MK_METHOD))
            for d in vmt.dynamic:
                name = declared.get(vmt.addr, {}).get(d["id"])
                claims.claim(d["addr"],
                             "%s.%s" % (cls, sanitize(name) if name
                                        else messages.handler_name(d["id"])),
                             depth, vmt.addr)
            for off, slot in P.std_methods(self.md.layout):
                claims.claim(self.md.reader.u32(vmt.addr + off),
                             "%s.%s" % (cls, slot), depth, vmt.addr)
            for index, name in slots.get(vmt.addr, {}).items():
                self._claim_slot(claims, vmt, index, name, depth, stubs)
            self._claim_interfaces(claims, vmt, depth)
            for prop in class_props.get(vmt.addr, []):
                pname = sanitize(prop["Name"])
                for accessor, verb in (("GetProc", "get"), ("SetProc", "set"),
                                       ("StoredProc", "stored")):
                    kind, value = P.decode_accessor(prop[accessor])
                    if kind == "static":
                        claims.claim(value, "%s.%s_%s" % (cls, verb, pname),
                                     depth, vmt.addr)
                    elif kind == "virtual":
                        self._claim_virtual(claims, vmt, value, verb, pname)

        self._claim_dfm(claims)
        for addr, name, owner, register_cc, kind in claims.resolved():
            self._name_function(addr, name, owner, register_cc, kind)
        self.stats["name_conflicts"] = claims.conflicts

    def _claim_dfm(self, claims):
        """Bind the form streams' event handlers to the code they name.

        The published method table has already claimed most of these
        addresses under the same name -- a handler is a published method, or
        the runtime could not resolve it -- so the claims settle rather than
        conflict, and what the form stream adds is the part no table carries:
        *which control and which event* reaches this code.  That goes in the
        comment.

        Accumulated, not overwritten.  One handler is routinely shared by a
        toolbar button, a menu item and an accelerator, and each of the three
        is a fact about the function; keeping only the last read would throw
        two of them away, and re-running the plugin over a database would
        churn the comment rather than converge.
        """
        if not self.opt["dfm_events"]:
            return
        md = self.md
        streams = dfm.find_streams(md.reader, dfm.view_ranges(self.bv))
        bindings, unbound = dfm.bind(md, streams)
        self.stats["dfm_streams"] = len(streams)
        self.stats["dfm_events_bound"] = len(bindings)
        self.stats["dfm_events_unbound"] = len(unbound)
        lines = {}
        for b in bindings:
            claims.claim(b.addr, "%s.%s" % (sanitize(b.form_vmt.name),
                                            sanitize(b.handler)),
                         len(md.class_chain(b.form_vmt)), b.form_vmt.addr)
            lines.setdefault(b.addr, []).append(b.comment())
        for addr, texts in sorted(lines.items()):
            try:
                have = self.bv.get_comment_at(addr) or ""
            except Exception:
                have = ""
            merged = [l for l in have.split("\n") if l] + texts
            self._comment(addr, "\n".join(dict.fromkeys(merged)))
        if streams:
            self.log("%d form streams, %d event handlers bound, %d unbound"
                     % (len(streams), len(bindings), len(unbound)))

    def _declared_indices(self, key):
        """class address -> {VirtualIndex: name} over the entries `key` picks.

        Merged along each class's chain, root first, so a class sees every
        index an ancestor declared as well as its own.  That is the direction
        both callers want and the only one that is sound: a name published by a
        descendant says nothing about an ancestor, which may not have the slot
        or the dynamic method at all.
        """
        own = {}
        for vmt in self.md.vmts.values():
            own[vmt.addr] = {m["virtual_index"]: m["name"]
                             for m in vmt.methods_ex if m.get(key)}
        out = {}
        for vmt in self.md.vmts.values():
            merged = {}
            for cls in self.md.class_chain(vmt):
                merged.update(own.get(cls.addr, {}))
            out[vmt.addr] = merged
        return out

    def _declared_dynamic_names(self):
        """class address -> {dynamic id: the name it was declared with}.

        A dynamic method table is two parallel arrays of ids and handlers with
        no names at all, so a plain `dynamic` method could only ever be called
        `DynMethod_m3` -- and where the class also published an extended entry
        for it, that name and the entry's real one tied at the same depth and
        both were dropped, leaving the handler unnamed.  The extended array is
        where the name is: an entry flagged FLAG_DYNAMIC carries the dispatch
        id in VirtualIndex instead of a vtable slot, and across the corpus all
        168 of them name an id that really is in the class's own or an
        inherited dynamic table, against the handler address the entry itself
        carries.  A message handler keeps its WM_/CM_/CN_ constant unless the
        binary names it, which it rarely does -- those are protected by
        convention, and pre-2010 nothing publishes a protected member at all.

        Inheriting the map down the chain is how dispatch itself works: an id
        is resolved by walking to the root, so whichever ancestor declared it
        fixes its meaning for the whole branch, and a descendant overriding it
        emits a table entry but often no extended entry of its own.
        """
        return self._declared_indices("dynamic")

    def _declared_slot_names(self):
        """class address -> {vtable slot index: declared name}.

        A VMT is a bare array of code pointers, so an override's name exists in
        the binary only where some class publishes an extended entry for the
        slot -- and that is the class which *declares* the method, not usually
        the one that overrides it.  Delphi's vtables are prefix extended: a
        descendant's table is its parent's followed by whatever the descendant
        adds, so slot `i` means the same method throughout a branch and a name
        declared anywhere up the chain is the right name for this class's slot,
        whatever address the class put there.

        Never the other way.  There is no way to recover how long an ancestor's
        vtable is -- `vtable_end` is only where a walk stopped finding code
        addresses, which over-runs into whatever the linker put next -- so
        carrying a descendant's name upwards would put a guess on a shallower
        class, and the shallowest claim is the one that wins.
        """
        return self._declared_indices("virtual")

    def _abstract_stubs(self):
        """The addresses an abstract method's vtable slot holds.

        `procedure Foo; virtual; abstract;` still occupies a slot, and the
        compiler fills it with System's @AbstractError -- one address shared by
        every abstract slot in the binary.  It is not any class's Foo, and
        naming it from a slot would hand the routine every abstract call in the
        program raises through one arbitrary class's method name: on
        ImageWriterSvc 184 slot claims land on it, and the shallowest of them
        would have called it `TMultiWaitEvent.WaitFor`.  The entries say which
        slots are abstract, so the addresses are read out of the binary rather
        than recognised from a signature.
        """
        ptr = self.md.layout.ptr_size
        out = set()
        for vmt in self.md.vmts.values():
            for m in vmt.methods_ex:
                if not m.get("abstract"):
                    continue
                addr = self.md.reader.ptr(vmt.addr + m["virtual_index"] * ptr)
                if addr:
                    out.add(addr)
        return out

    IUNKNOWN_SLOTS = ["QueryInterface", "_AddRef", "_Release"]

    def _claim_interfaces(self, claims, vmt, depth):
        """Name the thunks in each implemented interface's vtable.

        Delphi records the GUID of every interface a class implements but no
        method names for it, so only the three IUnknown slots every interface
        vtable starts with can be named properly.  The rest are numbered, and
        claimed at a deliberately low priority so any real name from a method
        or property table wins the slot instead.

        These claims carry no convention.  A thunk follows the convention its
        interface declares, not the one the class uses: IUnknown's three slots
        are stdcall, and their thunks adjust the instance pointer at [esp+4]
        rather than in EAX.
        """
        for entry in vmt.interfaces:
            iname = self.md.interface_names().get(entry["guid"], "IUnknown")
            vtable = entry["vtable"]
            if not vtable or not self.bv.is_valid_offset(vtable):
                continue
            for i in range(256):
                addr = self.md.reader.u32(vtable + 4 * i)
                if not addr or not self.md._is_code(addr):
                    break
                slot = (self.IUNKNOWN_SLOTS[i] if i < len(self.IUNKNOWN_SLOTS)
                        else "vtbl%d" % i)
                claims.claim(addr, "%s.%s_%s" % (sanitize(vmt.name),
                                                 sanitize(iname), slot),
                             depth + 1000, vmt.addr, register_cc=False)

    def _claim_slot(self, claims, vmt, index, name, depth, stubs):
        """Name whatever `vmt` put in vtable slot `index`.

        One class only -- the whole branch is covered because every class is
        offered the indices its ancestors declared.  A class that does not
        override the slot names its ancestor's implementation, which is the
        same claim the ancestor makes at a shallower depth and so settles
        rather than conflicts.
        """
        layout = self.md.layout
        if index < -layout.n_virtuals:
            return                             # a data slot, not a method one
        addr = vmt.addr + index * layout.ptr_size
        if index >= 0 and addr >= vmt.vtable_end:
            return                             # past this class's vtable
        target = self.md.reader.ptr(addr)
        if not target or target in stubs or not self.md._is_code(target):
            return
        claims.claim(target, "%s.%s" % (sanitize(vmt.name), sanitize(name)),
                     depth, vmt.addr)

    def _claim_virtual(self, claims, vmt, offset, verb, pname):
        """Name the slot `offset` in every class that shares it.

        The property names one virtual method, but that method occupies the
        same slot in the class that introduced it and in every descendant, so
        one published property can name a whole column of the hierarchy.  The
        shallowest claimant wins, which lands the name on the introducing
        class and leaves each override credited to the class that made it.
        """
        for other in self.md.hierarchy(vmt):
            slot = other.addr + offset
            if offset >= 0 and slot >= other.vtable_end:
                continue                       # slot past this class's vtable
            if offset < 0 and offset < -self.md.layout.header_size:
                continue
            claims.claim(self.md.reader.u32(slot),
                         "%s.%s_%s" % (sanitize(other.name), verb, pname),
                         len(self.md.class_chain(other)), other.addr)

    def _name_function(self, addr, name, owner=None, register_cc=True,
                       kind=None):
        """Name one function, and say what arrives in the convention's first
        argument register.

        Three shapes, and the metadata says which:  an ordinary method gets
        the instance, so Self is a pointer to the class struct;  a class
        method gets the metaclass -- the class pointer itself, where the
        vtable starts, which is exactly why the RTTI publishes no ParamType
        for that Self -- so a pointer to the instance struct would name every
        field at the wrong address;  and a static class method gets no Self at
        all, so the register holds the first real argument and asserting Self
        over it would rename and mistype a genuine parameter.
        """
        if not self.bv.is_valid_offset(addr) or not self.md._is_code(addr):
            return
        self_type = None
        if self.opt["self_param"] and owner and kind != P.MK_STATIC:
            vmt = self.md.vmts.get(owner)
            if vmt is not None:
                self_type = (Type.pointer(self.bv.arch, Type.void())
                             if kind == P.MK_CLASS_METHOD
                             else sinks.self_pointer(self.bv, self.factory,
                                                     vmt))
        if self.sink.add_function(addr, name, self_type, register_cc):
            self.stats["functions_named"] += 1

    def _finish(self):
        typed = self.sink.finish()
        self.stats["self_typed"] = typed or getattr(self.sink, "self_typed", 0)
        self.stats["functions_created"] = getattr(self.sink, "created", 0)
        # Read off the factory rather than the type-definition loop: the
        # literal record types are built on demand, as the data variables that
        # use them are declared.
        self.stats["enums"] = self.factory.enums
        self.stats["structs"] = self.factory.structs


# -------------------------------------------------------------- descriptions

def describe_typeinfo(md, ti):
    lines = ["%s %s" % (ti.kind_name, ti.name)]
    if ti.unit:
        lines[0] += "   (unit %s)" % ti.unit
    d = ti.data
    if ti.kind == 3:
        names = d.get("Names") or []
        lines.append("  %s %d..%d" % (d.get("OrdType"), d.get("MinValue"),
                                      d.get("MaxValue")))
        lines.append("  " + ", ".join(names))
    elif ti.kind == 7:
        lines.append("  class 0x%x, parent typeinfo 0x%x, %d published "
                     "properties (%d total incl. inherited)"
                     % (d.get("ClassType") or 0, d.get("ParentInfo") or 0,
                        len(ti.props), d.get("PropCount") or 0))
        for prop in ti.props:
            lines.append("    %-28s %s" % (prop["Name"], _prop_summary(md, prop)))
    elif ti.kind == 8:
        params = ", ".join("%s%s: %s" % ("".join(p["Flags"]) + " " if p["Flags"]
                                         else "", p["Name"], p["Type"])
                           for p in d.get("Params") or [])
        lines.append("  %s(%s)%s" % (d.get("MethodKind"), params,
                                     ": " + d["ResultType"]
                                     if d.get("ResultType") else ""))
    elif ti.kind == 15:
        lines.append("  %s parent=0x%x" % (d.get("GUID"),
                                           d.get("IntfParent") or 0))
    elif ti.kind == 14 and ti.fields:
        lines.append("  size %s, %d managed fields" % (d.get("Size"),
                                                       len(ti.fields)))
    elif d:
        lines.append("  " + ", ".join("%s=%s" % (k, v) for k, v in d.items()
                                      if k != "Names"))
    return "\n".join(lines)


def _prop_summary(md, prop):
    parts = []
    pt = md.typeinfo_by_ptr(prop["PropType"])
    parts.append(pt.name if pt else "?")
    for accessor, verb in (("GetProc", "read"), ("SetProc", "write"),
                           ("StoredProc", "stored")):
        kind, value = P.decode_accessor(prop[accessor])
        if kind == "field":
            parts.append("%s F+0x%x" % (verb, value))
        elif kind == "virtual":
            parts.append("%s vmt[%d]" % (verb, value))
        elif kind == "static":
            parts.append("%s 0x%x" % (verb, value))
    if prop["Index"] not in (None, -0x80000000):
        parts.append("index %d" % prop["Index"])
    return "  ".join(parts)


#: TParamFlag -> the Pascal keyword it stands for. The rest of the flags say
#: how the parameter is passed rather than how it was declared, so they do not
#: belong in a signature.
_PARAM_KEYWORDS = {"pfVar": "var", "pfConst": "const", "pfOut": "out"}

#: What the low three bits of TVmtMethodExEntry.Flags say the member is.
_METHOD_KINDS = {P.MK_STATIC: "static", P.MK_METHOD: "method",
                 P.MK_CLASS_METHOD: "class method",
                 P.MK_CONSTRUCTOR: "constructor",
                 P.MK_DESTRUCTOR: "destructor"}


def _method_summary(md, m):
    """`(Self: TFoo; const S: string): Integer   method ccReg vmt[39]`.

    Only names are resolved, never records: reading the kind byte and name a
    PPTypeInfo points at costs two dereferences, where parsing the record it
    points at would parse every published property of a class for each of the
    thousands of parameters a modern binary declares.

    A parameter the RTTI gives no type for is printed without one.  That is
    what the metadata says -- an untyped `var`, or the metaclass Self a class
    method receives -- and inventing a type for it would be a claim the
    binary does not make.
    """
    parts = []
    if m["params"] is not None:
        params = []
        for p in m["params"]:
            keywords = [_PARAM_KEYWORDS[f] for f in p["flag_names"]
                        if f in _PARAM_KEYWORDS]
            ptype = P.typeinfo_name(md.reader, p["type"])
            params.append("%s%s%s" % (
                "".join(k + " " for k in keywords), p["name"],
                ": " + ptype if ptype else ""))
        parts.append("(%s)" % "; ".join(params))
    result = P.typeinfo_name(md.reader, m["result_type"])
    if result:
        parts.append(": " + result)
    tail = [_METHOD_KINDS.get(m["method_kind"], "flags $%02x" % m["flags"]),
            m.get("cc")]
    if m.get("abstract"):
        tail.append("abstract")
    # The same field, read two ways, and Flags is what says which: a vtable
    # slot index or a dynamic dispatch id.  Printing an id as `vmt[-3]` is how
    # a plain dynamic method comes to look like a virtual one at a slot that
    # holds some unrelated function.
    if m.get("virtual"):
        tail.append("vmt[%d]" % m["virtual_index"])
    elif m.get("dynamic"):
        kind, name = messages.classify(m["virtual_index"])
        tail.append("%s[%s]" % ("dynamic" if kind == messages.MSG_KIND_INDEX
                                else "message", name))
    return "%s   %s" % ("".join(parts), " ".join(t for t in tail if t))


def describe_vmt(md, vmt):
    chain = " -> ".join(v.name for v in md.class_chain(vmt))
    unit, source = md.unit_for(vmt)
    header = "VMT %s" % vmt.name
    if unit:
        header += "   (unit %s%s)" % (
            unit, "" if source == "rtti" else ", inferred from neighbours")
    lines = [header,
             "  %s" % chain,
             "  instance size %s, %d virtual slots"
             % (vmt.instance_size, len(vmt.virtuals))]
    for f in vmt.fields:
        lines.append("  field  +0x%-5x %s" % (f["offset"], f["name"]))
    # The managed fields carry no name, so the comment is the only place their
    # real Pascal type is written down: the struct member is named after its
    # offset and typed structurally, and `TStringList` tells a reader far more
    # than `void *` does.
    for f in vmt.managed:
        lines.append("  managed +0x%-4x %s: %s%s"
                     % (f["offset"], managed_field_name(f), f["type_name"],
                        "   (inline %s, left unplaced)" % f["kind_name"]
                        if f["inline"] else ""))
    for m in vmt.methods:
        lines.append("  method 0x%08x %s" % (m["addr"], m["name"]))
    # The extended array repeats every classic entry as a record of its own,
    # so the ones already listed above are not listed twice; what is left is
    # everything the classic table never mentioned, which is nearly all of it.
    classic = {(m["addr"], m["name"]) for m in vmt.methods}
    for m in vmt.methods_ex:
        if (m["addr"], m["name"]) in classic:
            continue
        lines.append("  method 0x%08x %s%s" % (m["addr"], m["name"],
                                               _method_summary(md, m)))
    for d in vmt.dynamic:
        kind, name = messages.classify(d["id"])
        lines.append("  %-7s 0x%08x %s (0x%04x)"
                     % ("dynamic" if kind == "index" else "message",
                        d["addr"], name, d["id"] & 0xFFFF))
    for e in vmt.interfaces:
        lines.append("  intf   %s vtable 0x%x offset %d"
                     % (e["guid"], e["vtable"], e["offset"]))
    return "\n".join(lines)


# ------------------------------------------------------------------- exports

def to_json(md):
    out = {"classes": [], "types": [], "regions": []}
    for start, end in md.regions():
        out["regions"].append({"start": start, "end": end,
                               "length": end - start})
    for vmt in sorted(md.vmts.values(), key=lambda v: v.addr):
        unit, source = md.unit_for(vmt)
        out["classes"].append({
            "name": vmt.name, "unit": unit, "unit_source": source,
            "vmt": vmt.addr, "header": vmt.header,
            "instance_size": vmt.instance_size,
            "ancestry": [v.name for v in md.class_chain(vmt)],
            "fields": vmt.fields,
            "managed": [{"offset": f["offset"], "name": managed_field_name(f),
                         "kind": f["kind_name"], "type": f["type_name"],
                         "placed": not f["inline"]} for f in vmt.managed],
            "methods": [{"name": m["name"], "addr": m["addr"]}
                        for m in vmt.methods],
            "methods_ex": [
                {"name": m["name"], "addr": m["addr"], "entry": m["entry"],
                 "flags": m["flags"],
                 "kind": _METHOD_KINDS.get(m["method_kind"]),
                 # Two readings of one field, and neither is meaningful unless
                 # the flag beside it says so, so each is exported under its
                 # own key rather than as a raw number a consumer has to
                 # re-interpret.
                 "virtual_index": m["virtual_index"] if m["virtual"] else None,
                 "dynamic_id": m["virtual_index"] if m["dynamic"] else None,
                 "abstract": m["abstract"],
                 "cc": m["cc"],
                 "result_type": P.typeinfo_name(md.reader, m["result_type"]),
                 "params": [
                     {"name": p["name"], "flags": p["flag_names"],
                      "type": P.typeinfo_name(md.reader, p["type"])}
                     for p in m["params"] or []]}
                for m in vmt.methods_ex],
            "dynamic": [{"id": d["id"], "addr": d["addr"],
                         "message": messages.classify(d["id"])[1]}
                        for d in vmt.dynamic],
            "interfaces": vmt.interfaces,
            "virtual_slots": [a for _, a in vmt.virtuals],
        })
    for ti in sorted(md.typeinfos.values(), key=lambda t: t.addr):
        out["types"].append({
            "name": ti.name, "kind": ti.kind_name, "unit": ti.unit,
            "addr": ti.addr, "end": ti.end, "data": ti.data,
            "properties": [{k: v for k, v in p.items() if k != "addr"}
                           for p in ti.props],
        })
    return json.dumps(out, indent=2, default=str)
