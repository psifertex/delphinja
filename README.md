# Delphinja

Binary Ninja workflow for Delphi and the Visual Component Library (VCL). Includes:

- **Metadata recovery** parses binary metadata: virtual method tables (VMTs),
  published method/field/dynamic-method tables, interface tables and the full
  `TTypeInfo`/`TTypeData` runtime type information (RTTI) graph. Turns them into types, names and
  class layouts.
- **Borland demangler** a custom Borland symbols demangler.
- **Signature libraries** ([WARP](https://dev-docs.binary.ninja/guide/warp.html),
  Binary Ninja's signature format) cover what no binary carries: the ordinary virtual
  methods and unit-level runtime library (RTL) procedures that Delphi statically links and
  strips the symbols from. These ship with the plugin and are loaded on
  demand -- only the libraries matching the binary's Delphi era, once it has
  been detected -- so nothing has to be copied into a signature directory.
Delphi 2 through 10.x are supported, and Free Pascal 2.6 through 3.2. The VMT
layout is detected per binary, and every offset is derived from it rather than
written down, which is what lets one build read every era.

## Layout

    rtti/          the decoder and everything that applies what it finds
    integration/   how that reaches Binary Ninja: workflow, debug info, WARP
    signatures/    the .warp libraries, loaded on demand per binary
    tools/         standalone signature generation tools

Further reading:

- [tools/README.md](tools/README.md) -- how the shipped signature libraries are built.

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
names. It cannot remove functions or set comments; neither has an entry point in the debug info API.
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
| `rtti/parser.py` | Pure decoding. Reaches the binary only through a `Reader`, so it runs headless against a raw portable executable (PE) as easily as against a `BinaryView`. |
| `rtti/messages.py` | Message-id name tables for dynamic method dispatch |
| `rtti/sinks.py` | Where recovered facts get written. `ViewSink` mutates a BinaryView; `DebugInfoSink` contributes to a DebugInfo container. The recovery logic is destination-agnostic. |
| `rtti/apply.py` | Scanning, type construction, name claiming — everything shared by both destinations |
| `integration/debuginfo.py` | The DebugInfoParser: a cheap `is_valid` probe and `parse_info` |
| `demangler.py` | Borland/Delphi symbol demangler, registered as a `Demangler` |
| `integration/workflow.py` | The two module-workflow activities |
| `integration/signatures.py` | Registers the bundled `.warp` libraries into WARP's container cache |
| `__init__.py` | Settings, commands and registration |

