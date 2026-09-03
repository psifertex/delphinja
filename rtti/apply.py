"""Turn parsed Delphi metadata into Binary Ninja types, symbols and names."""

import bisect
import json
import re

import binaryninja as bn
from binaryninja import (BinaryView, Symbol, SymbolType, Type,
                         StructureBuilder, BaseStructure,
                         NamedTypeReferenceClass)

from . import messages
from . import parser as P
from . import sinks

TAG = "delphinja"
_BAD_CHARS = re.compile(r"[^A-Za-z0-9_.$]")


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

    def __init__(self, bv):
        self.bv = bv
        self._code_ranges = [
            (s.start, s.end) for s in bv.sections.values()
            if s.semantics in (bn.SectionSemantics.ReadOnlyCodeSectionSemantics,
                               bn.SectionSemantics.DefaultSectionSemantics)]
        # Scanning tests one dword per byte of code, so going through
        # bv.read() means a third of a million calls into the core, each
        # taking the view lock while this thread holds the GIL. Analysis is
        # running on other threads at the same time, so that serialises the
        # whole pipeline. Copy the code sections out once and scan memory.
        self._cache = []
        for start, end in self._code_ranges:
            try:
                data = bv.read(start, end - start)
            except Exception:
                data = b""
            if len(data) == end - start:
                self._cache.append((start, end, data))
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
        self._children = None
        self._interfaces = None
        self._uregions = None
        self._uevidence = None
        self._class_ti = None

    def _read(self, addr, length):
        for start, end, data in self._cache:
            if start <= addr and addr + length <= end:
                off = addr - start
                return data[off:off + length]
        return self.bv.read(addr, length)

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
        return self

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
        return sorted(out)

    def regions(self, gap=0x40, strings=True):
        """Coalesced metadata regions, the answer to 'where else is this?'."""
        return P.cluster([(s, e) for s, e, _ in self.spans(strings)], gap)

    def typeinfo_by_ptr(self, pptypeinfo):
        """PPTypeInfo cell -> parsed TypeInfo."""
        if not pptypeinfo or not self.bv.is_valid_offset(pptypeinfo):
            return None
        target = self.reader.u32(pptypeinfo)
        ti = self.typeinfos.get(target)
        if ti is None and target is not None:
            ti = P.parse_typeinfo(self.reader, target)
        return ti

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
    """Remove every function that overlaps any of `ranges`.

    Linear sweep happily disassembles RTTI, so these tables usually carry a
    handful of large bogus functions that poison xrefs and the call graph.
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
        if any(_overlaps(index, lo, hi) for lo, hi in covered):
            victims.append(f)
    for f in victims:
        if log:
            log("undefining %s at 0x%x (%d blocks)"
                % (f.name, f.start, len(f.basic_blocks)))
        if f.auto:
            bv.remove_function(f)
        else:
            bv.remove_user_function(f)
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
        """Published fields, plus the fields that published properties read."""
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

    def rtti_type(self, ti):
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
        if k in (13, 14):                                # array / record
            size = ti.data.get("Size") or 4
            return Type.array(Type.int(1, False), max(1, size))
        if k in (15, 17):                                # interface / dynarray
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

    def claim(self, addr, name, depth, owner=None, register_cc=True):
        if not addr:
            return
        best = self.claims.get(addr)
        if best is None or depth < best[1]:
            self.claims[addr] = (name, depth, False, owner, register_cc)
        elif depth == best[1] and name != best[0]:
            self.claims[addr] = (best[0], best[1], True, best[3], best[4])

    def resolved(self):
        for addr, (name, _, tied, owner, register_cc) in sorted(
                self.claims.items()):
            if tied:
                self.conflicts += 1
                continue
            yield addr, name, owner, register_cc


# -------------------------------------------------------------------- applier

VMT_HEADER_TYPE = "TVmtHeader"
# The eleven data slots. The virtual slots that follow them differ per era and
# are appended from P.std_methods(), so this table stays era-independent.
_VMT_DATA_FIELDS = [
    ("SelfPtr", "void*"), ("IntfTable", "void*"), ("AutoTable", "void*"),
    ("InitTable", "void*"), ("TypeInfo", "void*"), ("FieldTable", "void*"),
    ("MethodTable", "void*"), ("DynamicTable", "void*"),
    ("ClassName", "char*"), ("InstanceSize", "uint32"), ("Parent", "void*"),
]


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
        }
        self.opt.update(options or {})
        self.sink = sink or sinks.ViewSink(md.bv, md)
        self.factory = TypeFactory(md, self.opt["prefix"], self.sink)
        self.stats = {"functions_removed": 0, "functions_named": 0,
                      "functions_created": 0, "data_vars": 0,
                      "comments": 0, "enums": 0, "structs": 0,
                      "self_typed": 0, "name_conflicts": 0, "strings": 0}
        self.log_lines = []

    def log(self, msg):
        self.log_lines.append(msg)
        bn.log_info(msg, TAG)

    # -- top level --------------------------------------------------------

    def run(self):
        md = self.md
        self.log("%d VMTs, %d TypeInfo records, %d string constants, "
                 "%d metadata regions"
                 % (len(md.vmts), len(md.typeinfos), len(md.strings),
                    len(md.regions())))

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
        fields = _VMT_DATA_FIELDS + [(m, "code*") for _, m in P.std_methods(layout)]
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
            self.sink.set_comment(addr, text)
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
            self._bytes_var(start, end, "%s_%s" % (label, base))

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
        for vmt in self.md.vmts.values():
            depth = len(self.md.class_chain(vmt))
            cls = sanitize(vmt.name)
            for m in vmt.methods:
                claims.claim(m["addr"], "%s.%s" % (cls, sanitize(m["name"])),
                             depth, vmt.addr)
            for d in vmt.dynamic:
                claims.claim(d["addr"],
                             "%s.%s" % (cls, messages.handler_name(d["id"])),
                             depth, vmt.addr)
            for off, slot in P.std_methods(self.md.layout):
                claims.claim(self.md.reader.u32(vmt.addr + off),
                             "%s.%s" % (cls, slot), depth, vmt.addr)
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

        for addr, name, owner, register_cc in claims.resolved():
            self._name_function(addr, name, owner, register_cc)
        self.stats["name_conflicts"] = claims.conflicts

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

    def _name_function(self, addr, name, owner=None, register_cc=True):
        if not self.bv.is_valid_offset(addr) or not self.md._is_code(addr):
            return
        self_type = None
        if self.opt["self_param"] and owner:
            vmt = self.md.vmts.get(owner)
            if vmt is not None:
                self_type = sinks.self_pointer(self.bv, self.factory, vmt)
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
    for m in vmt.methods:
        lines.append("  method 0x%08x %s" % (m["addr"], m["name"]))
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
            "methods": [{"name": m["name"], "addr": m["addr"]}
                        for m in vmt.methods],
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
