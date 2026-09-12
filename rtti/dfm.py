"""Delphi form streams: the binary DFM format, and what it says about code.

A VCL application's forms are designed in the IDE and compiled into the
executable as one binary stream per form, stored as an RT_RCDATA resource
named after the form class.  The stream is what `TReader` replays at runtime
to construct the form: every control, every property the designer changed
from its default, and -- the part that matters to an analyst -- the *name* of
the method that handles each event.

    object := [prefix] ClassName ObjectName property* $00 child* $00

That is the whole grammar.  Values carry a `TValueType` tag, so the reader
never needs to know a property's declared type to skip it, which is why this
decoder can walk a stream for a VCL it has never seen.

The reason this is worth decoding is that a stripped Delphi GUI binary is
thousands of anonymous subroutines, and the form stream is the only place in
the file that says `Button1.OnClick = LoadFileClick`.  The address behind that
name comes from the *form class's* published method table -- Delphi resolves
handler names through `TObject.MethodAddress` against the root component's
class, never against the control that raised the event -- so binding is a
lookup of the DFM's identifier in the form's own method table, and the method
table is independent evidence, which makes every binding checkable.

Nothing here imports Binary Ninja: like `parser`, this talks to the binary
through a `Reader` and to the scan results through their plain attributes, so
it runs headless against a raw PE.
"""

import struct

from . import parser as P

#: Every stream starts with this, resource or not.  `TStream.WriteSignature`
#: writes it once at the head of the outermost object; nested objects carry no
#: signature of their own, so a magic scan finds forms, not controls.
MAGIC = b"TPF0"

#: TFilerFlags, packed into the low nibble of an object's optional prefix
#: byte.  The high nibble is $F, which is what distinguishes a prefix from the
#: length byte of a class name -- no ShortString in a form stream is 240
#: characters long.
FF_INHERITED, FF_CHILD_POS, FF_INLINE = 0x01, 0x02, 0x04
FILER_FLAGS = [(FF_INHERITED, "ffInherited"), (FF_CHILD_POS, "ffChildPos"),
               (FF_INLINE, "ffInline")]
PREFIX_MASK = 0xF0

#: TValueType, in declaration order.  The tail of the list is a version
#: history: vaSingle through vaWString arrived with Delphi 3, vaInt64 with 4,
#: and vaUTF8String and vaDouble with 2009, so an older stream simply never
#: emits the high ordinals.  Decoding all of them costs nothing and means one
#: decoder covers every era.
VALUE_TYPES = [
    "vaNull", "vaList", "vaInt8", "vaInt16", "vaInt32", "vaExtended",
    "vaString", "vaIdent", "vaFalse", "vaTrue", "vaBinary", "vaSet",
    "vaLString", "vaNil", "vaCollection", "vaSingle", "vaCurrency", "vaDate",
    "vaWString", "vaInt64", "vaUTF8String", "vaDouble",
]
VA = dict((name, i) for i, name in enumerate(VALUE_TYPES))

#: The integer tags `ReadInteger` accepts, for the two places a bare integer
#: appears: an ffChildPos position and a collection item's index.
INT_TAGS = (VA["vaInt8"], VA["vaInt16"], VA["vaInt32"])

#: Longest byte string accepted from a length field.  vaBinary carries icons,
#: images and Pascal scripts, so megabytes are ordinary; the cap exists only
#: to stop a length read out of unrelated bytes from swallowing a section.
MAX_BLOB = 0x1000000

#: Nesting depth accepted.  A form with a page control inside a panel inside a
#: frame is perhaps six deep; anything approaching this is a runaway parse.
MAX_DEPTH = 64

#: Properties or children accepted from one object, and objects from one
#: stream.  The largest form in the corpus is a few hundred controls.
MAX_ITEMS = 8192

#: What makes a published property an event rather than an ordinary one.
#: The value type alone is not enough: `Align = alClient` is a vaIdent too,
#: and binding on value type alone invents a handler for every enum-valued
#: property in the form.  Delphi's own naming rule is the discriminator, and
#: the length test is what keeps a property genuinely called `On` out.
EVENT_PREFIX = "On"


class Value(object):
    """One property value, kept tagged.

    The tag is not decoration.  Event detection turns on a value being a
    vaIdent specifically -- a handler name and a string that happens to look
    like one are different things -- and rendering a value for a human depends
    on which of the six numeric encodings it arrived in.
    """

    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    @property
    def tag_name(self):
        return (VALUE_TYPES[self.tag] if 0 <= self.tag < len(VALUE_TYPES)
                else "va%d" % self.tag)

    def __repr__(self):
        return "<%s %r>" % (self.tag_name, self.value)

    def text(self):
        """A one-line rendering, in the spirit of the textual DFM."""
        tag, v = self.tag, self.value
        if tag in (VA["vaString"], VA["vaLString"], VA["vaWString"],
                   VA["vaUTF8String"]):
            return "'%s'" % v.replace("'", "''")
        if tag == VA["vaSet"]:
            return "[%s]" % ", ".join(v)
        if tag == VA["vaList"]:
            return "(%s)" % " ".join(x.text() for x in v)
        if tag == VA["vaCollection"]:
            return "<%d item%s>" % (len(v), "" if len(v) == 1 else "s")
        if tag == VA["vaBinary"]:
            return "{%d bytes}" % len(v)
        if tag == VA["vaExtended"]:
            # An 80-bit x87 double-extended, which no other language here has.
            # Converting it to a Python float would quietly round it, and the
            # value is almost always a designer coordinate nobody needs in
            # decimal, so the bytes are shown as themselves.
            return "$" + v.hex().upper()
        if tag in (VA["vaFalse"], VA["vaTrue"]):
            return "True" if v else "False"
        if tag == VA["vaNil"]:
            return "nil"
        if tag == VA["vaNull"]:
            return ""
        return str(v)


class Prop(object):
    __slots__ = ("name", "value")

    def __init__(self, name, value):
        self.name = name
        self.value = value

    @property
    def is_event(self):
        """`OnClick = Button1Click` -- an identifier under an On* name.

        Both halves are load bearing.  A vaIdent under an ordinary name is an
        enumeration member (`Align = alClient`, `Cursor = crHandPoint`), and
        an On* property that is not a vaIdent is not a handler reference at
        all.  Requiring both is what makes the binding rate a real number
        rather than a count of guesses.
        """
        return (self.value.tag == VA["vaIdent"]
                and self.name.startswith(EVENT_PREFIX)
                and len(self.name) > len(EVENT_PREFIX))

    def __repr__(self):
        return "<Prop %s = %s>" % (self.name, self.value.text())


class Obj(object):
    """One `object` node: a form, or a control inside one."""

    def __init__(self, addr):
        self.addr = addr
        self.end = addr
        self.flags = 0
        self.position = None      # the ffChildPos ordinal, when there is one
        self.class_name = None
        self.name = None
        self.props = []
        self.children = []

    @property
    def flag_names(self):
        return [n for bit, n in FILER_FLAGS if self.flags & bit]

    def __repr__(self):
        return "<Obj %s: %s, %d props, %d children>" % (
            self.name, self.class_name, len(self.props), len(self.children))

    def walk(self):
        """This object and every descendant, parents first."""
        yield self
        for child in self.children:
            for node in child.walk():
                yield node

    def events(self):
        """(object, property) for every event assignment in the subtree."""
        for node in self.walk():
            for prop in node.props:
                if prop.is_event:
                    yield node, prop

    def count(self):
        return sum(1 for _ in self.walk())


# ------------------------------------------------------------ value decoding
#
# One reader per TValueType, looked up by ordinal.  Each takes the address
# just past the tag byte and returns (Value, address just past the value), or
# (None, None) when the bytes cannot be that encoding -- which is how a false
# TPF0 hit in the middle of a JPEG gets rejected rather than parsed.


def _fixed(fmt, size, tag, convert=None):
    def read(r, p):
        raw = r.bytes(p, size)
        if len(raw) != size:
            return None, None
        v = struct.unpack(fmt, raw)[0]
        return Value(tag, convert(v) if convert else v), p + size
    return read


def _empty(tag, value):
    def read(r, p):
        return Value(tag, value), p
    return read


def _shortstr(tag):
    def read(r, p):
        s, q = r.shortstr(p)
        return (Value(tag, s), q) if s is not None else (None, None)
    return read


def _longstr(tag, encoding, width=1):
    """vaLString, vaUTF8String and vaWString: a 32-bit count, then the text.

    The count is of *characters*, not bytes, which for vaWString is half the
    length -- Delphi wrote it with `Length(WideString)`.  Reading it as a byte
    count truncates every wide string in the stream at its midpoint and leaves
    the parse standing in the middle of a UTF-16 code unit, so the whole
    remainder of the form decodes as noise.
    """
    def read(r, p):
        n = r.u32(p)
        if n is None or n * width > MAX_BLOB:
            return None, None
        raw = r.bytes(p + 4, n * width)
        if len(raw) != n * width:
            return None, None
        return Value(tag, raw.decode(encoding, "replace")), p + 4 + n * width
    return read


def _binary(r, p):
    """vaBinary: a 32-bit byte count and that many bytes.

    These are the embedded icons, glyphs, bitmaps and -- in an Inno Setup or
    a scripting host -- whole Pascal script bodies.  The bytes are kept rather
    than skipped so a caller can carve them out; nothing in the binding path
    looks at them.
    """
    n = r.u32(p)
    if n is None or n > MAX_BLOB:
        return None, None
    raw = r.bytes(p + 4, n)
    if len(raw) != n:
        return None, None
    return Value(VA["vaBinary"], raw), p + 4 + n


def _extended(r, p):
    """vaExtended: the 80-bit x87 type, ten bytes, kept raw.

    Python has no 80-bit float and the value is nearly always a designer
    measurement, so converting would trade an exact ten bytes for an
    approximation nobody wanted.  `Value.text` prints the bytes.
    """
    raw = r.bytes(p, 10)
    return ((Value(VA["vaExtended"], raw), p + 10) if len(raw) == 10
            else (None, None))


def _set(r, p):
    """vaSet: the member names, terminated by a zero-length string.

    A set is written by name, not as a bitmask, because the ordinals of an
    enumeration are a compile-time detail of whichever VCL version wrote the
    form and the stream has to survive being read back by another one.
    """
    out = []
    for _ in range(MAX_ITEMS):
        n = r.u8(p)
        if n is None:
            return None, None
        if n == 0:
            return Value(VA["vaSet"], out), p + 1
        name, p = r.shortstr(p)
        if not P.is_identifier(name):
            return None, None
    return None, None


def _list(r, p):
    """vaList: values until a vaNull tag closes it."""
    out = []
    for _ in range(MAX_ITEMS):
        tag = r.u8(p)
        if tag is None:
            return None, None
        if tag == VA["vaNull"]:
            return Value(VA["vaList"], out), p + 1
        item, p = read_value(r, p)
        if item is None:
            return None, None
    return None, None


def _collection(r, p):
    """vaCollection: items until a zero byte, each a property list.

    An item may be preceded by a bare integer giving its index in the
    collection, which the writer emits only when the items are not being
    written in order -- an inherited form that changed one column of a grid
    writes that column alone, with its index.  The tag is checked rather than
    assumed, because there is no flag anywhere saying which form this is.

    Each item's properties are then wrapped in a list of their own: the writer
    calls WriteListBegin before them, so a vaList tag stands between the item
    and its first property name.  Reading the properties directly instead is
    the difference between decoding a form and not: a TListView's Columns, a
    SynEdit's Keystrokes and a TMainMenu's Items are all collections, so
    missing the wrapper abandons the parse in the middle of the main form of
    most real applications and leaves exactly the forms worth having
    undiscovered.
    """
    items = []
    for _ in range(MAX_ITEMS):
        tag = r.u8(p)
        if tag is None:
            return None, None
        if tag == VA["vaNull"]:
            return Value(VA["vaCollection"], items), p + 1
        index = None
        if tag in INT_TAGS:
            item, p = read_value(r, p)
            if item is None:
                return None, None
            index = item.value
        if r.u8(p) != VA["vaList"]:
            return None, None
        props, p = _read_props(r, p + 1)
        if props is None:
            return None, None
        items.append((index, props))
    return None, None


#: Ordinal -> reader.  Built as a table so that adding a TValueType is one
#: line and so nothing downstream tests an encoding by its number.
_READERS = {
    VA["vaNull"]: _empty(VA["vaNull"], None),
    VA["vaList"]: _list,
    VA["vaInt8"]: _fixed("<b", 1, VA["vaInt8"]),
    VA["vaInt16"]: _fixed("<h", 2, VA["vaInt16"]),
    VA["vaInt32"]: _fixed("<i", 4, VA["vaInt32"]),
    VA["vaExtended"]: _extended,
    VA["vaString"]: _shortstr(VA["vaString"]),
    VA["vaIdent"]: _shortstr(VA["vaIdent"]),
    VA["vaFalse"]: _empty(VA["vaFalse"], False),
    VA["vaTrue"]: _empty(VA["vaTrue"], True),
    VA["vaBinary"]: _binary,
    VA["vaSet"]: _set,
    VA["vaLString"]: _longstr(VA["vaLString"], "latin-1"),
    VA["vaNil"]: _empty(VA["vaNil"], None),
    VA["vaCollection"]: _collection,
    VA["vaSingle"]: _fixed("<f", 4, VA["vaSingle"]),
    # Currency is a scaled 64-bit integer: four implied decimal places.
    VA["vaCurrency"]: _fixed("<q", 8, VA["vaCurrency"], lambda v: v / 10000.0),
    VA["vaDate"]: _fixed("<d", 8, VA["vaDate"]),
    VA["vaWString"]: _longstr(VA["vaWString"], "utf-16-le", 2),
    VA["vaInt64"]: _fixed("<q", 8, VA["vaInt64"]),
    VA["vaUTF8String"]: _longstr(VA["vaUTF8String"], "utf-8"),
    VA["vaDouble"]: _fixed("<d", 8, VA["vaDouble"]),
}


def read_value(r, p):
    """Decode the tagged value at `p`.  (None, None) if the tag is not one."""
    tag = r.u8(p)
    reader = _READERS.get(tag)
    if reader is None:
        return None, None
    return reader(r, p + 1)


def _read_integer(r, p):
    """A bare `ReadInteger`: one of the three integer tags, nothing else."""
    if r.u8(p) not in INT_TAGS:
        return None, None
    value, p = read_value(r, p)
    return (value.value, p) if value is not None else (None, None)


# ----------------------------------------------------------- object decoding


def _read_props(r, p):
    """Properties until the zero byte that ends the list."""
    props = []
    for _ in range(MAX_ITEMS):
        n = r.u8(p)
        if n is None:
            return None, None
        if n == 0:
            return props, p + 1
        name, q = r.shortstr(p)
        if not P.is_identifier(name):
            return None, None
        value, q = read_value(r, q)
        if value is None:
            return None, None
        props.append(Prop(name, value))
        p = q
    return None, None


def _read_object(r, p, depth, budget):
    """One object node and its whole subtree.

    `budget` is a single-element list of the objects still allowed, shared by
    the recursion: a stream is bounded as a whole, not per level, because the
    shape a runaway parse takes is a long flat list of one-byte objects rather
    than deep nesting.
    """
    if depth > MAX_DEPTH or budget[0] <= 0:
        return None, None
    budget[0] -= 1
    obj = Obj(p)

    prefix = r.u8(p)
    if prefix is None:
        return None, None
    if prefix & PREFIX_MASK == PREFIX_MASK:
        obj.flags = prefix & ~PREFIX_MASK
        p += 1
        if obj.flags & FF_CHILD_POS:
            obj.position, p = _read_integer(r, p)
            if obj.position is None:
                return None, None

    obj.class_name, p = r.shortstr(p)
    if not P.is_identifier(obj.class_name):
        return None, None
    # An unnamed component is legal and common -- the designer only names what
    # the code refers to -- so an empty name is accepted where a class name
    # never is.
    obj.name, p = r.shortstr(p)
    if obj.name is None or (obj.name and not P.is_identifier(obj.name)):
        return None, None

    obj.props, p = _read_props(r, p)
    if obj.props is None:
        return None, None

    for _ in range(MAX_ITEMS):
        nxt = r.u8(p)
        if nxt is None:
            return None, None
        if nxt == 0:
            obj.end = p + 1
            return obj, p + 1
        child, p = _read_object(r, p, depth + 1, budget)
        if child is None:
            return None, None
        obj.children.append(child)
    return None, None


def parse_stream(r, addr):
    """Decode the form stream whose `TPF0` signature is at `addr`.

    Returns the root object, or None when the bytes after the signature are
    not a form.  Every field is validated as it is read and any failure
    rejects the whole stream, which is what makes a raw magic scan safe: the
    four bytes occur by chance inside compressed data, and a stream that does
    not decode end to end was never a form.
    """
    if r.bytes(addr, len(MAGIC)) != MAGIC:
        return None
    root, _ = _read_object(r, addr + len(MAGIC), 0, [MAX_ITEMS])
    return root


# ----------------------------------------------------------------- discovery


def view_ranges(bv):
    """The spans worth scanning for form streams.

    Forms live in the resource directory, which is neither code nor a place
    the RTTI scanner has any reason to look, so this deliberately does not
    reuse the metadata scanner's code ranges.  Readable segments are the
    honest answer to "where could a resource be", and they are what makes a
    magic scan find every stream in the file rather than only the ones a
    resource-directory walk successfully navigated to.
    """
    spans = [(s.start, s.end) for s in bv.segments
             if s.readable and s.end > s.start]
    return spans or [(bv.start, bv.end)]


#: Bytes pulled out of the view at a time while scanning.  Large enough that
#: the per-read overhead disappears, small enough not to copy a whole section
#: of a 40MB binary into one string.
_CHUNK = 0x100000


def find_streams(r, ranges, progress=None):
    """Every form stream in `ranges`, in address order.

    A magic scan, not a resource-directory walk.  The signature is four bytes
    with no alignment requirement, and scanning for it costs one pass over the
    file, whereas navigating the PE resource tree to RT_RCDATA finds only the
    forms the tree agrees are there -- which in practice misses the main form
    of most applications, because a resource entry can be reached by paths a
    walker does not follow, and because a form can be linked in as raw data
    with no resource entry at all.  The parse validates whatever the scan
    finds, so a chance signature inside a bitmap costs a rejected parse and
    nothing else.
    """
    out = []
    for start, end in ranges:
        addr, done = start, 0
        # One stream's vaBinary payload can hold another file entirely -- a
        # form with an embedded image of a form -- so a hit inside a stream
        # already decoded is not a second form.  The watermark also keeps a
        # stream that spans a chunk boundary from being parsed twice.
        past = start
        while addr < end:
            P.check_progress(progress, done, end - start)
            size = min(_CHUNK, end - addr)
            # Overlap by the signature length so a stream straddling a chunk
            # boundary is still found.
            data = r.bytes(addr, min(size + len(MAGIC) - 1, end - addr))
            off = data.find(MAGIC) if data else -1
            while 0 <= off < size:
                hit = addr + off
                if hit >= past:
                    root = parse_stream(r, hit)
                    if root is not None:
                        out.append(root)
                        past = max(past, root.end)
                off = data.find(MAGIC, off + 1)
            done += size
            addr += size
        P.check_progress(progress, done, end - start)
    out.sort(key=lambda o: o.addr)
    return out


# ------------------------------------------------------------------- binding


class Binding(object):
    """One resolved `Control.OnEvent = Handler`."""

    __slots__ = ("form", "form_vmt", "control", "control_class", "event",
                 "handler", "addr", "event_type", "signature")

    def __init__(self, form, form_vmt, control, control_class, event, handler,
                 addr, event_type=None, signature=None):
        self.form = form                  # the root object's name
        self.form_vmt = form_vmt          # Vmt the handler was resolved in
        self.control = control            # the object that raised the event
        self.control_class = control_class
        self.event = event                # 'OnClick'
        self.handler = handler            # the identifier the DFM names
        self.addr = addr                  # where that method actually is
        self.event_type = event_type      # 'TNotifyEvent', when recoverable
        self.signature = signature        # '(Sender: TObject)', when so

    @property
    def qualified(self):
        return "%s.%s" % (self.form_vmt.name, self.handler)

    def comment(self):
        """The line this binding contributes to its handler's comment.

        Named after the control and the event rather than the form, because
        the form is already in the function's name and the control is the
        thing an analyst is looking for: `lblEmail: TLabel.OnMouseEnter` says
        what the user did to get here.
        """
        text = "DFM: %s: %s.%s" % (self.control or "(unnamed)",
                                   self.control_class, self.event)
        if self.signature:
            text += " %s%s" % (self.event_type or "", self.signature)
        return text


def method_table(md, vmt):
    """Every published method name in `vmt`'s chain -> its address.

    Root first so a descendant's override replaces the ancestor's entry, which
    is how the runtime resolves it: `MethodAddress` walks from the class it
    was called on upwards and stops at the first match.

    Both arrays.  The classic table is where a pre-2010 form's handlers are,
    the extended one where a modern binary's are, and where both describe a
    method they agree, so merging them cannot disagree with itself.
    """
    out = {}
    for cls in md.class_chain(vmt):
        for m in cls.methods + cls.methods_ex:
            if m.get("name") and m.get("addr"):
                out[m["name"]] = m["addr"]
    return out


def _by_name(md):
    """Class name -> the VMTs carrying it.

    A name is not unique in general -- a binary that statically links a
    package can hold two classes of the same name -- so this keeps the list
    and lets the caller decide, rather than picking one silently.
    """
    out = {}
    for vmt in md.vmts.values():
        if vmt.name:
            out.setdefault(vmt.name, []).append(vmt)
    return out


def _resolve_form(md, root, by_name):
    """Which VMT the root object's class name refers to.

    Where one binary holds several classes of that name, the right one is the
    one that actually publishes the handlers this form names: a duplicate from
    a linked-in package publishes a different set, or none.  Scoring by that
    is evidence from the stream itself.  A genuine tie is dropped rather than
    guessed at -- the same rule the VMT name claims use -- because naming a
    handler on the wrong class is worse than leaving it unnamed.
    """
    candidates = by_name.get(root.class_name, [])
    if len(candidates) <= 1:
        return candidates[0] if candidates else None
    wanted = set(prop.value.value for _, prop in root.events())
    scored = [(len(wanted & set(method_table(md, vmt))), vmt)
              for vmt in candidates]
    best = max(score for score, _ in scored)
    winners = [vmt for score, vmt in scored if score == best]
    return winners[0] if len(winners) == 1 else None


def _event_signature(md, by_name, class_name, event):
    """The declared type of `class_name.event`, if the RTTI carries it.

    The DFM says which event was assigned; the control class's published
    property record says what that event's type is, and the tkMethod record
    behind it spells out the parameter list the handler must have.  So a
    `TNotifyEvent` resolves all the way to `(Sender: TObject)` out of metadata
    already in the file.

    Walked up the control's chain, because the property is published by
    whichever ancestor introduced it -- `OnClick` belongs to TControl, not to
    the TButton the designer dropped on the form.
    """
    candidates = by_name.get(class_name) or []
    if len(candidates) != 1:
        return None, None            # ambiguous class name: no honest answer
    for anc in reversed(md.class_chain(candidates[0])):
        ti = md.class_typeinfo(anc)
        if ti is None:
            continue
        for prop in ti.props:
            if prop["Name"] != event:
                continue
            return (P.typeinfo_name(md.reader, prop["PropType"]),
                    _params_text(_method_typeinfo(md, prop["PropType"])))
    return None, None


def _method_typeinfo(md, pptypeinfo):
    """The tkMethod record a property's PropType cell points at, if it is one."""
    r = md.reader
    if not pptypeinfo or not r.is_mapped(pptypeinfo):
        return None
    addr = r.ptr(pptypeinfo)
    if not addr or not r.is_mapped(addr):
        return None
    ti = md.typeinfos.get(addr) or P.parse_typeinfo(r, addr)
    return ti if ti is not None and ti.kind == 8 else None


def _params_text(ti):
    """'(Sender: TObject)' from a tkMethod record's parameter list."""
    if ti is None:
        return None
    parts = []
    for prm in ti.data.get("Params") or []:
        flags = "".join(f[2:].lower() + " " for f in prm.get("Flags") or []
                        if f in ("pfVar", "pfConst", "pfOut"))
        parts.append("%s%s: %s" % (flags, prm.get("Name") or "_",
                                   prm.get("Type") or "?"))
    text = "(%s)" % "; ".join(parts)
    result = ti.data.get("ResultType")
    return text + (": %s" % result if result else "")


def bind(md, streams, signatures=True):
    """Resolve every event assignment in `streams` against the form classes.

    Returns (bindings, unresolved), where unresolved counts the event
    assignments whose identifier is in no published method table reachable
    from the form's class -- the honest denominator for a binding rate.
    """
    by_name = _by_name(md)
    bindings, unresolved = [], []
    for root in streams:
        vmt = _resolve_form(md, root, by_name)
        if vmt is None:
            unresolved += [(root, node, prop) for node, prop in root.events()]
            continue
        table = method_table(md, vmt)
        sigs = {}
        for node, prop in root.events():
            addr = table.get(prop.value.value)
            if not addr:
                unresolved.append((root, node, prop))
                continue
            event_type = sig = None
            if signatures:
                key = (node.class_name, prop.name)
                if key not in sigs:
                    sigs[key] = _event_signature(md, by_name, *key)
                event_type, sig = sigs[key]
            bindings.append(Binding(root.name, vmt, node.name, node.class_name,
                                    prop.name, prop.value.value, addr,
                                    event_type, sig))
    return bindings, unresolved
