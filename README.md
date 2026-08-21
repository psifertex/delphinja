# Delphinja

Binary Ninja workflow for Delphi and the Visual Component Library (VCL). Includes:

- **Metadata recovery** parses binary metdata like VMTs,
  published method/field/dynamic-method tables, interface tables and the full
  `TTypeInfo`/`TTypeData` RTTI graph. Turns them into types, names and
  class layouts.
- **Borland demangler** a custom Borland symbols demangler.
- **Signature libraries** cover what no binary carries: the ordinary virtual
  methods and unit-level RTL procedures that Delphi statically links and
  strips the symbols from. These ship with the plugin and are registered at
  load, so nothing has to be copied into a signature directory.
Delphi 2 through 10.x are supported. The VMT layout is detected per binary.

## Layout

    rtti/          the decoder and everything that applies what it finds
    integration/   how that reaches Binary Ninja: workflow, debug info, WARP
    signatures/    the .warp libraries, registered at load
    tools/         standalone signature generation tools

## How it runs

The plugin registers three things:

**One decoder, two delivery mechanisms**, chosen by the `delphinja.mechanism`
setting. It is read at plugin load, so changes require a restart. Both apply
the same data just in different ways.

- `workflow` (default) — two activities spliced into
`core.module.metaAnalysis`. The first runs immediately before
`core.module.extendedAnalysis`, which is where linear sweep lives: defining the
metadata as data first minimizes bogus function creation. The second runs after
`core.module.deleteUnusedAutoFunctions`, removing whatever still overlaps, and
types `Self`. Both jobs need that late position — parameter variables do not
exist until functions are analysed, and a removal made any earlier is silently
undone.
- `debugInfo` — a `DebugInfoParser` contributing types, data variables and
names. It does not functions or set comments.
- `off` — nothing automatic; the registered commands still work.

**A Borland demangler** — Binary Ninja ships MSVC, Itanium, LLVM and Swift
demanglers but nothing for Borland, so `@Classes@TReader@ReadIdent$qqrv` passed
through untouched. Needed for any symbol source that carries Borland mangling
(package exports, DCUs); the RTTI path produces demangled names already.

**Plugin commands** — for everything the debug info API cannot express, and for
repairing databases analysed before the parser existed:

| Command | What it does |
| --- | --- |
| `Delphi\Report metadata regions` | Read-only scan; report of every metadata region, unit and class |
| `Delphi\Apply metadata (types, symbols, names)` | The full pipeline against the view, including comments and undefining |
| `Delphi\Export metadata to JSON` | Every parsed record, for use outside Binary Ninja |
| `Delphi\Undefine functions in selection` | Removes every function overlapping the selected range |
| `Delphi\Apply metadata in selection` | Scans and applies within the selection only |
| `Delphi\Describe record at address` | Decodes the VMT or RTTI record under the cursor into the log |

## What gets applied

1. **Undefines** functions overlapping metadata records. 
2. **Creates types**: a struct per class with `base_structures` inheritance and
   the real instance size, an enum per `tkEnumeration`, plus `TVmtHeader` and
   `TMethod`. Field offsets are recovered from published field tables and
   from the field-mapped accessors in published property tables, then assigned
   to whichever ancestor's slice of the instance actually contains them.
3. **Resolves the unit** each class belongs to and qualifies its symbols
   (`VMT_Classes_TReader`). Only classes compiled with `$M+` — everything
   descended from `TPersistent` — carry a `tkClass` record, and the unit name
   lives in that record, so `TReader`, `TList` and `TStream` have a VMT and a
   class name but no unit. The linker emits each unit's metadata
   contiguously, so a class whose metadata region contains RTTI records that
   all name the same unit is placed in that unit; regions with mixed or no
   evidence are left unresolved rather than guessed at. Every comment and the
   JSON export record whether a unit was read or inferred. 
4. **Defines data variables and symbols** over every record, so the region
   renders as data and `mov eax, [0x41ad78]` reads as `PTypeInfo_TColor`.
5. **Comments** each record with its decoded contents — property list with
   accessor kinds, class ancestry, message table with resolved names.
6. **Names functions** from published method tables, dynamic/message tables,
   property accessors and the standard VMT slots. An address shared by several
   classes is credited to the shallowest one in the hierarchy; genuine ties
   between unrelated classes are left alone rather than guessed at.
7. **Types `Self`** (the first parameter, EAX under Delphi's register
   convention) as the owning class, which is what makes field accesses in the
   decompiler render as named members.

## What metadata cannot reach

Delphi emits metadata for classes and published members only. Ordinary virtual
methods and unit-level RTL procedures carry no metadata and require signatures.

## What this cannot recover

Delphi emits metadata for classes, published members and types. It emits
nothing for unit-level procedures, and a VMT is a bare array of pointers with
no parallel name table, so an ordinary virtual method's name exists nowhere in
the binary. In the test binary 1205 code addresses are reachable from RTTI and
636 can be named; the remainder are vtable slots with no anchor. Naming RTL
routines like `Classes.ReadError` requires additional WARP signatures.

## Measured accuracy

Against the 96-binary corpus gathered for testing, with all fifteen signature
libraries registered and the binary's own RTTI as independent ground truth:

    91,518 functions matched
    precision on overlapping names: 2904/2919 = 99.5%

The fifteen remaining disagreements are all cross-version VCL confusions --
`Grids::TCustomDrawGrid::TopLeftChanged` matched where the binary's metadata
says `TJvCustomRichEdit` -- which is what similar VCL code across versions
costs. Full run in `tools/eval-96-all-versions.log`.

Two caveats worth knowing before reading that number:

- The same measurement reported 59% before dynamic method tables were checked
  for validity. Nearly all of those "disagreements" were bad ground truth
  rather than bad signatures: a misread table slot produced 205,090 bogus
  claims on one binary alone. A precision figure is only as good as the truth
  it is measured against.
- Registering all fifteen libraries at once is not free. On a 30-file
  comparison, loading only the matching version matched *more* functions on 11
  of 30 binaries than loading all fifteen -- several libraries claiming the
  same GUID makes the matcher ambiguous and it declines the match. Selecting a
  library by detected version would recover those.

## Accuracy notes

`messages.py` maps dynamic-method ids to `WM_*` / `CM_*` / `CN_*` names. The
`WM_` and `CN_` tables are Win32 constants; the `CM_` table covers
`CM_BASE + 0..55` from `Controls.pas` and reports anything beyond that as
`CM_BASE_<n>` rather than inventing a name. Every applied name is also written
into the record comment together with the raw id, so a wrong entry in that
table is visible and reversible. Edit the table freely.

## Modules

| File | Contents |
| --- | --- |
| `rtti/parser.py` | Pure decoding. Reaches the binary only through a `Reader`, so it runs headless against a raw PE as easily as against a `BinaryView`. |
| `rtti/messages.py` | Message-id name tables for dynamic method dispatch |
| `rtti/sinks.py` | Where recovered facts get written. `ViewSink` mutates a BinaryView; `DebugInfoSink` contributes to a DebugInfo container. The recovery logic is destination-agnostic. |
| `rtti/apply.py` | Scanning, type construction, name claiming — everything shared by both destinations |
| `integration/debuginfo.py` | The DebugInfoParser: a cheap `is_valid` probe and `parse_info` |
| `demangler.py` | Borland/Delphi symbol demangler, registered as a `Demangler` |
| `integration/workflow.py` | The two module-workflow activities |
| `integration/signatures.py` | Registers the bundled `.warp` libraries into WARP's container cache |
| `__init__.py` | Settings, commands and registration |

# Signature libraries

## Where the names come from

[Interactive Delphi Reconstructor](https://github.com/crypto2011/IDR) ships
prebuilt knowledge bases for Delphi 2 through XE6, **MIT licensed**, at
[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR). Each
holds per-procedure name, code bytes and a per-byte relocation mask, harvested
from the shipped `.dcu` files — the exact bytes the linker copies into an
executable. No Delphi installation is required.

## How it works

A knowledge-base procedure is a standalone code dump with **no address**; its
cross-references survive only as *named* fixups. So the pipeline reconstructs an
executable-shaped image:

1. **Stage** every procedure into one synthetic image.
2. **Relink** each fixup operand to point at its target's address in that image.
3. **Analyse** the image in Binary Ninja and name every procedure.
4. **Generate** the `.warp` with `WarpProcessor`, and save the database.

Step 2 is not cosmetic. Binary Ninja's value analysis and no-return detection
read *through* call operands, and WARP hashes what analysis produces rather than
raw bytes. Measured against a real Delphi 7 binary: **1178 matches with
relinking, 337 without** — 3.5x.

## Why one image and not batches

Analysis scales at roughly O(n^1.95) in function count (2020 procs → 60s,
10107 → 1400s), so the full knowledge base in a single image takes about four
hours, and batching looked like the obvious fix. It is not:

- A call crossing a batch boundary cannot be relinked, and relinking is worth 3.5x.
- The RTL is densely interconnected — the median module's dependency closure is
  7181 of 41467 procedures.
- Pinning the core (the 16 modules used by more than half of all units, 5073
  procedures) into every batch costs **exactly the same four hours** as
  analysing everything at once, and still loses cross-batch calls.

So: one image, one run, and save the database. That database is the expensive
artifact — regenerating the library from it costs seconds.

## Reversible decisions

Nothing is filtered at staging time. Short thunks make poor signatures, but
dropping them during staging would keep them out of the saved database too.
Instead everything is staged and named, and inclusion is decided at generation
time, where `WarpProcessor(included_functions=...)` can take all functions,
only annotated ones, or only those carrying the `WARP: Selected Function` tag.

## Naming

`Unit::Class::Member` — matching Binary Ninja's `QualifiedName` convention and
the Borland demangler, rather than Pascal's dotted source syntax. These names
are destined for the public WARP server alongside libraries from every other
toolchain, so they should read like the rest of Binary Ninja.

## Usage

Every version, unattended and resumable -- results land in `signatures/`, which
is what the plugin registers at load:

    python3 tools/build_all.py

One knowledge base:

    python3 tools/run.py <kb7.bin> <workdir> <out.warp>

Both put the repository root on `sys.path` and import `tools` directly rather
than going through the `delphinja` package -- importing the package would run
the plugin's `__init__` and register the recovery workflow inside the build
process, where it would then run against the staged image and remove functions
from it. `tools/evaluate.py` is the exception: it *wants* the decoder, so it
adds the repository's parent and imports `delphinja.rtti`.

Note that WARP reads a container's sources when the container is created, so a
library written by a running process is not visible to it -- generate and test
in separate processes.

## Modules

| File | Contents |
| --- | --- |
| `tools/kb.py` | IDR knowledge base reader (format spec in the module docstring) |
| `tools/stage.py` | Synthetic image staging and fixup relinking |
| `tools/types.py` | Delphi type strings and calling conventions to Binary Ninja types |
| `tools/classes.py` | Real class structs from knowledge base type records |
| `tools/naming.py` | The one naming convention |
| `tools/generate.py` | Analysis, naming and `.warp` generation |
| `tools/build_all.py` | Builds every version, unattended and resumable |
| `tools/evaluate.py` | Corpus evaluation and precision measurement |
| `tools/run.py` | CLI for a single knowledge base |

## Attribution

Knowledge base data ©crypto2011, MIT licensed. 
