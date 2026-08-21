"""Delphi class layouts recovered from the knowledge base type section.

The signature library's prototypes are only as good as the types in them, and
without this every class reference degrades to `void*` -- so a matched RTL
function reads `Self_1->__offset(0x8).d` where it could read `Self_1->FCount`.

The knowledge base carries what is needed: 16,542 type records for Delphi 7,
each with its own fields (name, absolute offset within the instance, type), and
a `decl` of the form `class(TParent)` giving the hierarchy. Field offsets are
absolute, so each class contributes only the fields it introduces and inherits
the rest through a base structure, exactly as Delphi lays the instance out.

Note that a type record's `size` is 4 for every class: a Delphi class variable
is a reference. The instance size has to be derived from the fields.
"""

import re

from binaryninja import BaseStructure, NamedTypeReferenceClass, StructureBuilder, Type

KIND_CLASS = ord('F')

_PARENT = re.compile(r"class\s*\(\s*([A-Za-z_][\w.]*)\s*\)")
_BAD = re.compile(r"[^A-Za-z0-9_]")


def _clean(name):
    return _BAD.sub("_", name.rsplit(".", 1)[-1])


class ClassIndex(object):
    """Every class the knowledge base describes, keyed by bare name."""

    def __init__(self, kb, type_map):
        self.kb = kb
        self.type_map = type_map
        self.classes = {}
        self._width = {}
        self._defined = set()
        self._load()

    def _load(self):
        for i in range(self.kb.sections['types'][0]):
            rec = self.kb.type_(i)
            if rec['kind'] != KIND_CLASS:
                continue
            name = _clean(rec['name'])
            if name in self.classes:
                continue                      # first definition wins
            match = _PARENT.search(rec.get('decl') or "")
            self.classes[name] = {
                "parent": _clean(match.group(1)) if match else None,
                "fields": rec.get('fields') or [],
            }

    # -- layout ----------------------------------------------------------

    def width(self, name, _seen=None):
        """Instance size, derived from the furthest field of the hierarchy."""
        if name in self._width:
            return self._width[name]
        _seen = _seen or set()
        if name in _seen or name not in self.classes:
            return 4
        _seen.add(name)
        cls = self.classes[name]
        end = self.width(cls["parent"], _seen) if cls["parent"] else 4
        for f in cls["fields"]:
            t = self.type_map.resolve(f["type"], classes=None)
            size = t.width or 4
            end = max(end, f["offset"] + size)
        self._width[name] = end
        return end

    def parent_width(self, name):
        cls = self.classes.get(name)
        return self.width(cls["parent"]) if cls and cls["parent"] else 4

    # -- emission --------------------------------------------------------

    def define(self, bv, name, _depth=0):
        """Register a struct for `name` and its ancestors. Returns the type name."""
        if name not in self.classes or _depth > 64:
            return None
        if name in self._defined:
            return name
        self._defined.add(name)                # guard cycles before recursing

        cls = self.classes[name]
        parent = cls["parent"]
        parent_name = self.define(bv, parent, _depth + 1) if parent else None
        base = self.parent_width(name)

        sb = StructureBuilder.create()
        sb.packed = True
        sb.width = max(self.width(name), base, 4)
        if parent_name:
            sb.base_structures = [BaseStructure(
                Type.named_type_reference(
                    NamedTypeReferenceClass.StructNamedTypeClass, parent_name),
                0, base)]
        else:
            sb.add_member_at_offset(
                "__vmt", Type.pointer(bv.arch, Type.void()), 0)

        for f in cls["fields"]:
            # Anything below the parent's extent is already described by the
            # base structure; adding it again would overlap.
            if f["offset"] < base or f["offset"] >= sb.width:
                continue
            try:
                sb.add_member_at_offset(
                    _clean(f["name"]),
                    self.type_map.resolve(f["type"], classes=self),
                    f["offset"])
            except Exception:
                pass

        bv.define_user_type(name, Type.structure_type(sb))
        return name

    def define_all(self, bv):
        for name in list(self.classes):
            try:
                self.define(bv, name)
            except Exception:
                pass
        return len(self._defined)

    def reference(self, bv, name):
        """Pointer to the class struct, defining it on demand."""
        defined = self.define(bv, _clean(name))
        if defined is None:
            return None
        return Type.pointer(bv.arch, Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, defined))
