# Form streams: from anonymous subroutine to "this runs when you click Button1"

A VCL application is mostly event handlers, and a stripped one is thousands of
anonymous subroutines. The binary already says which of them handles the click
on which button — it has to, because that is how the form is built at runtime —
and `rtti/dfm.py` reads it.

Compiling a form writes the designer's work into the executable as a binary
stream, one per form, stored as an `RT_RCDATA` resource named after the form
class. `TReader` replays it at startup to construct the form. Every property
the designer changed is in there, and so is the *name* of the method that
handles each event.

## The grammar

    object := [prefix] ClassName ObjectName property* $00 child* $00

That is the whole of it. The stream begins with the four bytes `TPF0` and one
top-level object; children carry no signature of their own.

The optional prefix byte exists when its high nibble is `$F` — no ShortString
in a form is 240 characters long, which is what makes the byte unambiguous. Its
low nibble is `TFilerFlags`: `ffInherited`, `ffChildPos` (followed by an
integer position), `ffInline`.

A property is a ShortString name and a value tagged with its `TValueType`, so
the reader never needs to know a property's declared type in order to skip it.
That is why one decoder covers a VCL it has never seen, and every third-party
component library along with it.

### The 22 value encodings

| Tag | Encoding | Notes |
| --- | --- | --- |
| `vaNull` | — | also the list terminator |
| `vaList` | values until `vaNull` | |
| `vaInt8` / `vaInt16` / `vaInt32` | 1 / 2 / 4 bytes, signed | |
| `vaExtended` | 10 bytes | the 80-bit x87 type; kept raw and printed as hex rather than rounded into a `double` |
| `vaString` / `vaIdent` | ShortString | identical on the wire; the tag is the whole difference, and it is what event detection turns on |
| `vaFalse` / `vaTrue` / `vaNil` | — | value is in the tag |
| `vaBinary` | `Int32` byte count, then bytes | icons, glyphs, bitmaps, and whole Pascal script bodies |
| `vaSet` | member names, ended by a zero-length string | written by name, never as a bitmask, so the stream survives a VCL whose enumeration ordinals moved |
| `vaLString` | `Int32` count, then bytes | |
| `vaCollection` | items until `$00` | see below |
| `vaSingle` / `vaDouble` | 4 / 8 bytes | |
| `vaCurrency` | `Int64`, four implied decimals | |
| `vaDate` | 8 bytes, `TDateTime` | |
| `vaWString` | `Int32` **character** count, then count × 2 bytes | |
| `vaInt64` | 8 bytes | |
| `vaUTF8String` | `Int32` byte count, then bytes | |

The tail of that list is a version history — `vaSingle` through `vaWString`
arrived with Delphi 3, `vaInt64` with 4, `vaUTF8String` and `vaDouble` with
2009 — so an older stream simply never emits the high ordinals, and decoding
all of them costs nothing.

Two encodings are worth spelling out because getting them wrong does not fail
loudly, it fails at the next byte and takes the rest of the form with it.

**`vaWString` counts characters, not bytes.** The writer wrote
`Length(WideString)`. Reading it as a byte count truncates every wide string at
its midpoint and leaves the parse standing inside a UTF-16 code unit.

**A `vaCollection` item's properties are wrapped in a list of their own.** The
writer calls `WriteListBegin` before them, so a `vaList` tag stands between the
item and its first property name. This one decides whether the implementation
works at all: a `TListView`'s `Columns`, a `SynEdit`'s `Keystrokes` and a
`TMainMenu`'s `Items` are all collections, so missing the wrapper abandons the
parse in the middle of the *main* form of most real applications, and leaves
exactly the forms worth having undiscovered. Before that one line was right,
this found 12 of the corpus's 16 sample forms; after it, 16.

## Finding the streams: magic scan, not a resource walk

Forms are found by scanning every readable segment for `TPF0`. The obvious
alternative — navigate the PE resource directory to the `RT_RCDATA` entries —
finds only the forms the tree walk successfully reaches, and a competing Ghidra
plugin that takes that route misses the main form of most applications it
handles. A magic scan costs one pass over the file, has no alignment
requirement to get wrong, and the parse validates whatever it turns up.

Validation is what makes the scan safe. Every field is checked as it is read —
class name a plausible identifier, property name likewise, every length inside
a cap, nesting and item counts bounded — and any failure rejects the whole
stream rather than salvaging a prefix of it. `TPF0` occurs by chance, and the
four bytes are also a real constant: `Classes.FilerSignature` is `$30465054`,
which is `TPF0` sitting in `.data` in every VCL binary ever built, referenced
by `TReader` and `TWriter` themselves.

Measured over the whole corpus, 113 binaries:

| | |
| --- | --- |
| raw `TPF0` occurrences | 503 |
| decoded end to end as forms | 435 |
| rejected | 68 |
| rejects whose next bytes resemble a class name | **0** |

The 68 rejects are the `FilerSignature` constant (one or two copies per
binary), other `.data` constants, and instruction bytes in `.text`. The
in-memory scan finds exactly the same 435 streams a raw scan of the files on
disk finds, so nothing is lost to segment mapping either.

## Binding an event to code

A property is an event **iff** its value is a `vaIdent` *and* its name starts
with `On` and is longer than two characters. Both halves matter. A `vaIdent`
under an ordinary name is an enumeration member — `Align = alClient`,
`Cursor = crHandPoint` — so binding on the value type alone invents a handler
for every enum-valued property in the form, and there are far more of those
than events.

The identifier is then resolved in the **root form class's** published method
table, never the control's. `Button1.OnClick = LoadFileClick` means
`TForm1.LoadFileClick`: the runtime resolves handler names with
`TObject.MethodAddress` against the component being read, walking its class
chain to the root, which is why a handler must be `published` to be assignable
at all. So the lookup merges both method arrays — the classic table, where a
pre-2010 binary keeps its handlers, and the extended one, where a modern binary
does — along the form's whole ancestry, root first so an override replaces what
it overrides.

Where the binary holds two classes of the same name, the one that actually
publishes the handlers this form names wins; a genuine tie is dropped rather
than guessed at, the same rule the VMT name claims use.

Nothing here names a function directly. Each binding is a claim into the same
`NameClaims` arbitration everything else goes through, at the form class's
depth, so the depth preference and tie-dropping apply unchanged and both
delivery mechanisms pick it up.

## What it produces

The name is `<FormClass>.<Handler>`, and it is nearly always the name the
published method table produced anyway — a handler *is* a published method.
The part no table carries is which control and which event reach that code, and
that goes in the comment:

    DFM: lblEmail: TLabel.OnMouseEnter TNotifyEvent(Sender: TObject)
    DFM: FileNewItem: TMenuItem.OnClick TNotifyEvent(Sender: TObject)

Comments accumulate rather than overwrite. One handler is routinely shared by a
toolbar button, a menu item and an accelerator, each of which is a separate
fact about the function; keeping only the last read would throw two of them
away and would churn the comment on every re-run instead of converging.

### Where the signature comes from

The stream names the event; the control class's published property record names
that event's *type*; and the `tkMethod` record behind it spells out the
parameter list, which `parse_typeinfo` already decodes. So `OnClick` on a
`TButton` resolves through `TControl.OnClick: TNotifyEvent` to
`procedure(Sender: TObject)` out of metadata already in the file, and
`OnCloseQuery` to `(Sender: TObject; var CanClose: Boolean)`. The property is
looked up along the control's ancestry, because `OnClick` belongs to `TControl`
and not to the `TButton` the designer dropped on the form.

That signature is **written into the comment and not asserted as a prototype**,
deliberately. Under Delphi's `register` convention the first three parameters —
`Self` included — travel in EAX, EDX and ECX and the rest are pushed, so one
mis-sized parameter transposes every stack argument after it, and a wrong
prototype is worse than none. The `tkMethod` record gives parameter types as
*names* (`TShiftState`, `TMouseButton`, `Boolean`), and turning those into
Binary Ninja types correctly means knowing the width of every set and
enumeration the VCL declares. The convention and `Self` are asserted — those
the class metadata proves — and the rest is documentation.

## Results

The four GUI samples, against the raw `TPF0` count in each file:

| Binary | Era | `TPF0` | forms | non-forms rejected | events bound | unbound |
| --- | --- | --- | --- | --- | --- | --- |
| `corpus/gh_delphidoom/Launcher.exe` | Delphi 7 | 5 | 4 | 1 | 42 | 0 |
| `corpus/grid2htm/Demo.exe` | Delphi 5 | 6 | 5 | 1 | 20 | 0 |
| `corpus/innosetup/Compil32.exe` | Delphi 3.02 | 6 | 5 | 1 | 102 | 0 |
| `corpus/gpopulation/bm.exe` | Delphi 4 | 3 | 2 | 1 | 21 | 0 |

Across all 113 corpus binaries: 435 forms, 5,283 events bound, 5,219 of them
with a recovered signature, in 2.1 seconds of scanning for the whole corpus.

Of the 393 event assignments that did not bind, 390 are forms whose class has
no VMT in the scan at all — SpaceSniffer yields no VMTs of any kind, and the
Delphi 2 build of Compil32 predates the layout the scanner reads — so there is
no method table to look a handler up in and the failure is upstream of this
module. The remaining **3, of 5,286 assignments against a known class**, name a
method the class's published tables do not list.

## Cost and control

One pass over the readable segments, which is the only part of the plugin that
looks outside the code sections. It has its own setting, `delphinja.dfm`, and
its own `Applier` option, `dfm_events`, so its cost and its results can be
attributed on their own. `dfm_streams`, `dfm_events_bound` and
`dfm_events_unbound` are reported in the applier statistics.

## What is deliberately not done

- **`vaBinary` blobs are decoded but not extracted.** They are the embedded
  icons, glyphs, bitmaps and — in Inno Setup and other scripting hosts — whole
  Pascal script bodies. The bytes are kept on the parsed value so a caller can
  carve them out; nothing does yet.
- **No data variable or symbol is defined over the stream itself.** The streams
  sit in the resource directory, where the PE loader has its own ideas about
  what the bytes are.
- **Non-event properties are parsed and discarded.** The full property tree is
  available on the parsed object; only events are applied.
