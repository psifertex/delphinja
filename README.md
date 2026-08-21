# Delphi

Binary Ninja support for Delphi and the VCL. Two complementary halves:

- **Metadata recovery** reads what the *binary itself* carries -- VMTs,
  published method/field/dynamic-method tables, interface tables and the full
  `TTypeInfo`/`TTypeData` RTTI graph -- and turns it into types, names and
  class layouts. It also demangles Borland symbols.
- **Signature libraries** cover what no binary carries: the ordinary virtual
  methods and unit-level RTL procedures that Delphi statically links and
  strips the symbols from. These ship with the plugin and are registered at
  load, so nothing has to be copied into a signature directory.

Delphi 2 through 10.x are supported. The VMT layout is detected per binary
rather than assumed, which is what makes a single build work across the era
boundaries (64-byte headers in Delphi 2, 76 through 2007, 88 from 2009 on).

## Layout

    rtti/          the decoder and everything that applies what it finds
    integration/   how that reaches Binary Ninja: workflow, debug info, WARP
    signatures/    the .warp libraries, registered at load
    tools/         how those libraries are built; not imported at load

`rtti/parser.py` has no Binary Ninja dependency at all, so the decoder can be
run and tested against a raw file.

## Requirements

The x86 `register` calling convention needs two core fixes to be laid out
correctly: callee stack cleanup, and the hidden pointer for an indirectly
returned result going in the argument slot *following* the declared
parameters (EAX with no parameters, EDX after one, the stack once EAX/EDX/ECX
are taken). Without them, every Delphi prototype with a stack argument or a
string/record/variant result has its arguments shifted.

## Why it matters

Delphi puts this metadata in `CODE`, so linear sweep disassembles it into large
bogus functions that pollute the call graph and xrefs, while the names it
contains — including the application's own form class, its components and its
event handlers — never reach analysis.

## How it runs

The plugin registers three things:

**One decoder, two delivery mechanisms**, chosen by the `delphi.mechanism`
setting. It is read at plugin load, so changing it needs a restart. Both drive
the same parser, scanner, type construction and naming through a sink; they
differ only in where results are written and when.

- `workflow` (default) — two activities spliced into `core.module.metaAnalysis`.
  The first runs immediately before `core.module.extendedAnalysis`, which is
  where linear sweep lives: defining the metadata as data first stops most bogus
  functions from ever existing. The second runs after
  `core.module.deleteUnusedAutoFunctions`, removes whatever still overlaps, and
  types `Self`. Both jobs need that late position — parameter variables do not
  exist until functions are analysed, and a removal made any earlier is silently
  undone.
- `debugInfo` — a `DebugInfoParser` contributing types, data variables and names.
  It cannot remove functions or set comments; neither has an entry point in the
  debug info API at any layer.
- `off` — nothing automatic; the commands still work.

Measured on a Delphi 7 sample, sweep-created functions overlapping metadata:
**107** with recovery off, **2** under `debugInfo`, **0** under `workflow` —
which also sets 346 comments that the debug info path cannot express.

The VMT layout is **detected, not assumed**. A hardcoded 76-byte header is right
only for Delphi 3 through 2007; 2009 onwards use 88 even on 32-bit, so assuming
it makes the scanner silently blind to modern binaries. On one Delphi 10.3
sample, detection is the difference between 0 and 1,068 recovered classes.

**A Borland demangler** — Binary Ninja ships MSVC, Itanium, LLVM and Swift
demanglers but nothing for Borland, so `@Classes@TReader@ReadIdent$qqrv` passed
through untouched. Needed for any symbol source that carries Borland mangling
(package exports, DCUs); the RTTI path produces unmangled names already.

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

Comments and function removal have no entry point in the debug info API at any
layer, so they stay on the command path.

## What gets applied

1. **Undefines** functions overlapping a metadata record. Overlap is tested
   against each record's *exact* span and against the function's actual basic
   blocks — Delphi interleaves real helper routines between its tables, and a
   coarser test deletes them.
2. **Creates types**: a struct per class with `base_structures` inheritance and
   the real instance size, an enum per `tkEnumeration`, plus `TVmtHeader` and
   `TMethod`. Field offsets are recovered from published field tables *and*
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
   JSON export record whether a unit was read or inferred. Leave-one-out
   against the classes that do carry a unit: 49 correct, 6 abstentions, 0
   wrong.
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

Existing user names are never overwritten.

## What metadata cannot reach

Delphi emits metadata for classes and published members only. Ordinary virtual
methods and unit-level RTL procedures carry no name anywhere in the binary, and
no amount of parsing reaches them -- that needs signature matching, which is
what the bundled libraries below provide. The two halves are complementary:
recovery supplies what the binary carries, signatures supply what it does not.

## What this cannot recover

Delphi emits metadata for classes, published members and types. It emits
nothing for unit-level procedures, and a VMT is a bare array of pointers with
no parallel name table, so an ordinary virtual method's name exists nowhere in
the binary. In the test binary 1205 code addresses are reachable from RTTI and
636 can be named; the remainder are vtable slots with no anchor. Naming RTL
routines like `Classes.ReadError` requires signature matching (IDA uses FLIRT
for exactly this), not deeper parsing.

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

Interactive Delphi Reconstructor ships prebuilt knowledge bases for Delphi 2
through XE6, **MIT licensed**, at https://github.com/crypto2011/IDR. Each holds
per-procedure name, code bytes and a per-byte relocation mask, harvested from
the shipped `.dcu` files — the exact bytes the linker copies into an executable.
No Delphi installation is required.

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

Both need the repository's parent directory on `sys.path`, since the tools
import `delphi.tools`; `build_all.py` arranges that itself.

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

Knowledge base data © crypto2011, MIT licensed. Any published signature library
derived from it inherits that attribution requirement.
