"""Turn parsed Delphi metadata into Binary Ninja types, symbols and names."""

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
            self._children = None
            self._interfaces = None
            self._uregions = None
            self._uevidence = None
            self._class_ti = None
        return self

    # -- derived views ----------------------------------------------------

    def spans(self):
        """Every (start, end, label) byte range that metadata occupies."""
        out = []
        for ti in self.typeinfos.values():
            start = ti.ptr_addr if ti.ptr_addr is not None else ti.addr
            out.append((start, ti.end, "TypeInfo %s" % ti.name))
        for v in self.vmts.values():
            out.append((v.header, v.vtable_end, "VMT %s" % v.name))
            for s, e, label in v.regions:
                out.append((s, e, "%s %s" % (label, v.name)))
        return sorted(out)

    def regions(self, gap=0x40):
        """Coalesced metadata regions, the answer to 'where else is this?'."""
        return P.cluster([(s, e) for s, e, _ in self.spans()], gap)

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
        if self._uregions is None:
            self._uregions = self.regions(self.UNIT_REGION_GAP)
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

def undefine_functions(bv, ranges, log=None):
    """Remove every function that overlaps any of `ranges`.

    Linear sweep happily disassembles RTTI, so these tables usually carry a
    handful of large bogus functions that poison xrefs and the call graph.
    """
    victims = []
    for f in list(bv.functions):
        # Test the blocks the function actually covers, not start..highest:
        # a real function with a far outlined tail can span a metadata region
        # it never touches, and removing that would be a real loss.
        try:
            covered = [(r.start, r.end) for r in f.address_ranges]
        except Exception:
            covered = [(b.start, b.end) for b in f.basic_blocks]
        if any(lo < end and hi > start
               for lo, hi in covered for start, end in ranges):
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

    def claim(self, addr, name, depth, owner=None):
        if not addr:
            return
        best = self.claims.get(addr)
        if best is None or depth < best[1]:
            self.claims[addr] = (name, depth, False, owner)
        elif depth == best[1] and name != best[0]:
            self.claims[addr] = (best[0], best[1], True, best[3])

    def resolved(self):
        for addr, (name, _, tied, owner) in sorted(self.claims.items()):
            if tied:
                self.conflicts += 1
                continue
            yield addr, name, owner


# -------------------------------------------------------------------- applier

VMT_HEADER_TYPE = "TVmtHeader"
_VMT_HEADER_FIELDS = [
    ("SelfPtr", "void*"), ("IntfTable", "void*"), ("AutoTable", "void*"),
    ("InitTable", "void*"), ("TypeInfo", "void*"), ("FieldTable", "void*"),
    ("MethodTable", "void*"), ("DynamicTable", "void*"),
    ("ClassName", "char*"), ("InstanceSize", "uint32"), ("Parent", "void*"),
    ("SafeCallException", "code*"), ("AfterConstruction", "code*"),
    ("BeforeDestruction", "code*"), ("Dispatch", "code*"),
    ("DefaultHandler", "code*"), ("NewInstance", "code*"),
    ("FreeInstance", "code*"), ("Destroy", "code*"),
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
                      "self_typed": 0, "name_conflicts": 0}
        self.log_lines = []

    def log(self, msg):
        self.log_lines.append(msg)
        bn.log_info(msg, TAG)

    # -- top level --------------------------------------------------------

    def run(self):
        md = self.md
        self.log("%d VMTs, %d TypeInfo records, %d metadata regions"
                 % (len(md.vmts), len(md.typeinfos), len(md.regions())))

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
            self.stats["enums"] = self.factory.enums
            self.stats["structs"] = self.factory.structs

        if self.opt["data_vars"] or self.opt["comments"]:
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
        ptr = Type.pointer(self.bv.arch, Type.void())
        for i, (fname, kind) in enumerate(_VMT_HEADER_FIELDS):
            t = (Type.int(4, False) if kind == "uint32"
                 else Type.pointer(self.bv.arch, Type.char()) if kind == "char*"
                 else ptr)
            sb.add_member_at_offset(fname, t, i * 4)
        sb.width = P.VMT_HEADER_SIZE
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
            width=P.VMT_HEADER_SIZE), "VMT_" + base)
        n = len(vmt.virtuals)
        if n:
            self._data(vmt.addr, Type.array(
                Type.pointer(self.bv.arch, Type.void()), n),
                "vtable_" + base)
        self._comment(vmt.header, describe_vmt(self.md, vmt))
        for start, end, label in vmt.regions:
            self._bytes_var(start, end, "%s_%s" % (label, base))

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
            for off, slot in P.VMT_STD_METHODS:
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

        for addr, name, owner in claims.resolved():
            self._name_function(addr, name, owner)
        self.stats["name_conflicts"] = claims.conflicts

    IUNKNOWN_SLOTS = ["QueryInterface", "_AddRef", "_Release"]

    def _claim_interfaces(self, claims, vmt, depth):
        """Name the thunks in each implemented interface's vtable.

        Delphi records the GUID of every interface a class implements but no
        method names for it, so only the three IUnknown slots every interface
        vtable starts with can be named properly.  The rest are numbered, and
        claimed at a deliberately low priority so any real name from a method
        or property table wins the slot instead.
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
                             depth + 1000, vmt.addr)

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
            if offset < 0 and offset < -P.VMT_HEADER_SIZE:
                continue
            claims.claim(self.md.reader.u32(slot),
                         "%s.%s_%s" % (sanitize(other.name), verb, pname),
                         len(self.md.class_chain(other)), other.addr)

    def _name_function(self, addr, name, owner=None):
        if not self.bv.is_valid_offset(addr) or not self.md._is_code(addr):
            return
        self_type = None
        if self.opt["self_param"] and owner:
            vmt = self.md.vmts.get(owner)
            if vmt is not None:
                self_type = sinks.self_pointer(self.bv, self.factory, vmt)
        if self.sink.add_function(addr, name, self_type):
            self.stats["functions_named"] += 1

    def _finish(self):
        typed = self.sink.finish()
        self.stats["self_typed"] = typed or getattr(self.sink, "self_typed", 0)
        self.stats["functions_created"] = getattr(self.sink, "created", 0)


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
