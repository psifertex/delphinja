# The runtime-package signature library

The fourth source in `tools/`, after IDR knowledge bases ([README.md](README.md)),
Free Pascal object files ([FPC.md](FPC.md)) and a modern binary's own extended
RTTI ([RTTI.md](RTTI.md)).

[RTTI.md](RTTI.md) exists because IDR's knowledge bases stop at XE6 and nothing
else publishes the compiled RTL. That is true of the *whole* RTL; it is not
true of a **runtime package**. A `.bpl` is an ordinary PE DLL that a Delphi
installation builds out of the same `.dcu` files a statically linked executable
draws on, and applications that link against packages redistribute it. So where
one can be had, it is a far richer input than a binary's own metadata.

## What a package supplies against what a `.warp` build needs

A knowledge-base procedure is a detached code dump: no address, cross-references
surviving only as named fixups, and a per-byte relocation mask that `stage.py`
has to turn back into something analysable. A package has none of those
problems, because the compiler already solved them.

| A `.warp` build needs | A knowledge base gives | A package gives |
| --- | --- | --- |
| a name per function | the procedure record | the export table, Borland-mangled |
| the code bytes | a dump | the mapped image |
| which bytes are relocatable | a per-byte mask to reconstruct | `.reloc`, read by the PE loader |
| addresses so calls resolve | nothing — `stage.py` relinks | the linker already resolved them |
| a prototype | the argument records | the mangled name's argument list |
| a unit name | the module record | the `PACKAGEINFO` resource |

So the pipeline is the four steps of README.md with the first two already done:
load, name, tag, generate. `stage.py` is not used at all, except for its rule
about which bodies are too small to be worth a signature.

### Where an export points

At the routine. Measured on `vcl50.bpl`: of 8,749 exports, 8,556 point into the
code section and **8,552 of those are exactly a function start**; two are
five-byte jumps. There is no import-thunk indirection to see through, because a
package exports its own code rather than re-exporting somebody else's.

### What an export names

Everything in a unit's interface — which crucially includes **unit-level
procedures**, the largest of the three categories extended RTTI cannot reach.
`System.SysUtils::GetLocaleFile` and `Vcl.Imaging.GIFImg::TGIFFrame::Decompress`
come out of the same table.

Not everything an export names is a function, though, and a Delphi image keeps
its type descriptors and VMTs *in the code section*, where analysis makes
functions of them. So exports are filtered by what the mangling says they are
rather than by where they point. On `vcl50.bpl`:

| kind | exports |
| --- | ---: |
| function | 6,001 |
| type descriptor (`$xp$`) | 1,269 |
| data | 657 |
| vtable | 454 |
| constructor | 231 |
| destructor | 135 |
| not Borland-mangled | 2 |

## The rules

A reading is kept only when all of these hold.

| Rule | Why |
| --- | --- |
| the mangling says function or destructor | a type descriptor and a VMT are not code, and see constructors below |
| the leading components spell a unit the package contains | `PACKAGEINFO` is the authority on where the unit name ends and the class begins, and a name that cannot be placed is not RTL |
| no other export name claims that address | the linker folds identical bodies, and a folded body is evidence against both names |
| the body is not a degenerate stub | `stage.is_thunk`, the same rule the knowledge-base pipeline applies |
| no other name in the build claims that function GUID | the same collision test, one level further on |
| no already-shipped library claims that GUID | see below |

### Constructors are dropped, destructors are kept

Borland's mangling collapses every Delphi constructor to `$bctr` and
distinguishes them only by argument types, so the member name — `Create`,
`CreateFmt`, `CreateRes` — is simply not in the string. Measured against the
shipped Delphi 5 library, of the 195 constructor exports it also names, 175 are
`Create`: **89.7%**, far below the standard the rest of this library holds to.
Restricting to classes with exactly one constructor export lifts that to 162 of
163, but a 99.4% rule beside a 99.9% one is still the rule that would produce
the errors, so constructors go.

Destructors are the opposite case and are kept, spelled `Destroy`. All 122 that
the Delphi 5 library also names are `Destroy`, which is what Delphi's
single-destructor convention predicts.

### A generic's argument list is dropped

`System.Generics.Collections::TList__1<TAcceptValueItem *>::InsertRange` becomes
`System.Generics.Collections::TList__1::InsertRange`. The package instantiates
the RTL's generics with the RTL's own types and an application instantiates them
with its own; where the two have the same layout the compiler emits the same
code, so a signature naming the package's instantiation would be confidently
wrong about every other one. The argument list is the only part that is wrong.
Dropping it also merges instantiations that folded into one body, which turns
what would have been two names for one address into one name for one address.

### Why the shipped GUIDs are excluded

The same reason as [RTTI.md](RTTI.md), and the same measurement follows from it.
A library is selected by VMT era and Delphi has not changed the standard virtual
count since 2009, so this library loads beside `delphi-rtl-2009`..`2014` and
`xe2plus` for every Unicode-era binary. Two loaded libraries claiming one GUID
under two different names is an ambiguity the matcher resolves by declining,
which would cost a match the older library was already making.

## Naming

`Vcl.Imaging.GIFImg::TGIFFrame::Decompress` — `naming.qualify`'s convention with
the unit's dots left alone, the same as `delphi-rtl-2011`..`2014` and
`xe2plus`. The unit's spelling comes from `PACKAGEINFO` rather than from the
mangled name, which is the only reason it can: the mangling writes
`@System@Sysutils@`, normalising the case and losing the namespace dots
entirely, and there is no way back from that string alone.

A compiler helper is rewritten from the mangling's `__linkproc__ GetMem` to the
knowledge bases' `@GetMem`, so that one routine has one spelling across the
libraries.

## Measured

### The method, on ground truth

`vcl50.bpl` is the controlled case: `signatures/delphi-rtl-5.warp` describes the
same Delphi 5 runtime, built from an entirely unrelated input — the `.dcu` files
the compiler wrote, by way of IDR's knowledge base — so every address both can
name is a test with ground truth on both sides. `tools/bpleval.py` registers the
library, analyses the package, and compares.

| | |
| --- | ---: |
| functions Binary Ninja finds in `vcl50.bpl` | 14,070 |
| exports this pipeline names | 6,134 |
| of those, `delphi-rtl-5.warp` matches | 4,685 |
| **identical name** | **4,660 (99.47%)** |

All 25 that differ are cases where the *package* is right:

* 19 are unit initialisation code, which a knowledge base names after its unit
  (`classes::Classes`) and a package names `Classes::initialization`;
* 4 are WARP matching a byte-identical sibling — `TListColumns::GetItem` for
  `TStatusPanels::GetItem`, `TCustomGrid::ResizeCol` for `ResizeRow`;
* 2 are the library naming a body after an import stub (`_DllGetActivationFactory@8`).

None is the export table being wrong about anything. Normalising the
initialisation spelling would read 4,679 of 4,685, or 99.87%.

The same test on `vcl40.bpl` against `delphi-rtl-4.warp`: 13,079 functions,
5,703 named, 4,486 matched, **4,462 identical — 99.47%**, with the same three
shapes of disagreement and again none of them the export table.

### What fraction of a package it names

This is the number that decides whether the route is worth taking, and it is
well short of everything.

| | `vcl50.bpl` | `rtl270.bpl` | `vcl270.bpl` | `vclimg270.bpl` |
| --- | ---: | ---: | ---: | ---: |
| exports | 8,749 | 49,388 | 12,375 | 819 |
| units contained | 90 | 303 | 51 | 8 |
| named by this pipeline | 6,134 | 16,069 | 7,645 | 482 |
| of those, on a function start | 6,134 | 16,069 | 7,645 | 482 |
| functions Binary Ninja finds | 14,069 | not measured | 39,136 | 2,309 |
| code section bytes | 1,425,112 | 7,370,076 | 2,767,496 | 243,580 |
| bytes of named functions | 502,818 | not measured | 860,979 | 58,196 |

Two things that table says. First, **every** named export lands exactly on a
function start, in all four packages — the export table needs no
reconciliation with analysis at all. Second, the fraction is between a fifth
and a half depending on which denominator, and neither denominator is quite
honest: a Delphi image keeps its type information in the code section, so
Binary Ninja's function count is inflated by data it walked into, and the code
section's size is inflated by the same data. The byte figure — 35% of
`vcl50.bpl`'s code section, 31% of `vcl270.bpl`'s — is the better of the two
and is still a floor.

An export table names a unit's *interface*. Everything in an implementation
section — a unit's local helpers, a nested procedure, an anonymous method body —
has no external linkage and no export, and neither do the compiler's own
generated bodies. So a package names a large minority of its own functions, not
all of them.

### The 10.4 Sydney library

Built from `rtl270.bpl`, `vcl270.bpl` and `vclimg270.bpl` together.

| | |
| --- | ---: |
| exports the three packages name | 24,196 |
| usable after the thunk and size rules | 22,223 |
| candidate function GUIDs | 14,377 |
| dropped: folded onto another name | 1,429 |
| dropped: GUID already shipped | 5,131 |
| **kept** | **8,661** (7,950 distinct names) |
| of those, carrying a prototype | 10,028 of 10,222 named functions |
| distinct units | 157 |
| **unit-level procedures** | **727** |
| file size | 2.6 MB |
| build time | 136 min, of which 125 is analysing `rtl270.bpl` |

The 727 unit-level procedures and the prototypes on 98% of the rest are the
two things [RTTI.md](RTTI.md)'s library cannot have at all. For scale, that
library holds 2,156 functions and no types, and shares no GUID with this one.

#### Precision, held out

None of the corpus was an input: the library comes from three runtime packages
and the ground truth from metadata each program carries about itself. For six
Unicode-era binaries, every function this library matched *and* the binary's
own extended RTTI also names was compared on both the class and the member
name, with generic argument lists and the mangling's `__N` arity suffix
normalised away.

| sample | Delphi | judged | agree | |
| --- | --- | ---: | ---: | ---: |
| `CodeCoverage.exe` | 10.4 Sydney | 213 | 211 | 99.06% |
| `ImageWriterSvc.exe` | 12 Athens | 107 | 106 | 99.07% |
| `DX.HttpDiag-Win32.exe` | 13 Florence | 98 | 98 | 100% |
| `BatteryMode32.exe` | 11 Alexandria | 11 | 9 | 81.82% |
| `Linkbar.exe` | 10.3 Rio | 8 | 7 | 87.50% |
| `Magicmida.exe` | 12 Athens | 5 | 5 | 100% |
| **total** | | **442** | **436** | **98.64%** |

All six failures are one shape, and it is the shape RTTI.md reports too: a body
too small or too generic for WARP to tell from a sibling. Four of the six are
destructors — `Vcl.ExtCtrls::TSplitter::Destroy` for `TImage.Destroy`,
`System.Win.WinRT::TWindowsString::TWindowsStringNexus::Destroy` for
`TGPBrush.Destroy` — which is where keeping destructors costs something. The
other two name `System.Classes::TStringList::Get` and `::Put` where the binary
says `TJclStringList`, a descendant that inherits both verbatim; the code
really is `TStringList`'s.

Two limits on that number. It is **442 comparisons out of 8,661 functions**,
because the only independent ground truth a binary carries is its extended
RTTI, and what this library adds over `xe2plus` — unit-level procedures,
prototypes — is exactly what that metadata does not describe. And the lever on
the residual failures, a floor on basic blocks rather than on bytes, was
identified and not measured: a rebuild costs two hours.

The controlled tests on `vcl40.bpl` and `vcl50.bpl` are the stronger evidence
for the method itself — 9,171 comparisons, 99.47% on both.

The third check is the one RTTI.md reports: of the GUIDs a
shipped library also carries, how many carry the same name? Measured on
`vcl270.bpl` and `vclimg270.bpl` (the `rtl270.bpl` half was not re-measured,
because it costs two hours of analysis): of 2,092 such GUIDs, **1,748 (83.6%)
match a name a shipped library gives the same code**. The residue is dominated
by era spelling rather than by disagreement — `Graphics::CreateMappedBmp` for
`Vcl.Graphics::CreateMappedBmp`, `GIFimg::GIFImg` for
`Vcl.Imaging.GIFImg::initialization` — and by bodies small enough that the
shipped library's own name for them is a coin toss. The whole overlap is
dropped regardless.

### Recall

`tools/evaluate.py` over ten binaries, three times before and three times
after, in the documented single-process invocation. Every figure below is the
three runs' median, with the spread across them in the last column; the
run-to-run spread is small enough here that the differences are not noise.

| sample | Delphi | WARP before | WARP after | | spread |
| --- | --- | ---: | ---: | ---: | ---: |
| `BatteryMode32.exe` | 11 Alexandria | 2,593 | 3,726 | +1,133 | 0 / 7 |
| `Linkbar.exe` | 10.3 Rio | 2,907 | 3,986 | +1,079 | 0 / 0 |
| `ImageWriterSvc.exe` | 12 Athens | 2,612 | 3,411 | +799 | 10 / 0 |
| `Magicmida.exe` | 12 Athens | 2,138 | 2,826 | +688 | 0 / 0 |
| `CodeCoverage.exe` | 10.4 Sydney | 1,751 | 2,398 | +647 | 0 / 0 |
| `DX.HttpDiag-Win32.exe` | 13 Florence | 1,347 | 1,753 | +406 | 0 / 0 |
| `TestActiveDirectory.exe` | XE2 | 3,921 | 4,280 | +359 | 1 / 2 |
| `Launcher.exe` | 7 | 3,260 | 3,269 | +9 | 0 / 0 |
| `Compil32.exe` | 3.02 | 1,750 | 1,755 | +5 | 1 / 1 |
| `Demo.exe` | 5 | 4,206 | 4,209 | +3 | 1 / 0 |

Between +30% and +44% on every Unicode-era binary, including three releases —
11, 12 and 13 — that this library was not built from, because much of the RTL
does not change between releases. The three pre-Unicode binaries are the
regression set and cannot load this library at all; they move by single digits,
which is what a library registered for a later binary in the same process does
to an earlier one, and it is the same in both directions.

### About `evaluate.py`'s aggregate precision

It reads 82.6% before and 81.4% after (three runs each; 82.5–82.7 and
81.3–81.4), which looks like a small loss and is not one. That metric splits
the binary's RTTI name at its first `.`, so a generic instantiation is compared
as `TList<System`, and it can never match any spelling of the name. Split by
whether either side looks generic, over three binaries with this library
loaded:

| | | |
| --- | ---: | ---: |
| plain names | 2,887 / 3,011 | **95.9%** |
| generic names | 1 / 605 | 0.2% |
| total | 2,888 / 3,616 | 79.9% |

This library is generic-heavy — 1,698 of its entries carry the mangling's `__N`
arity suffix — so it adds mostly rows the metric cannot score, and the
aggregate falls while the count of correctly named functions rises by 557.
RTTI.md notes the same artifact for the same reason.

The arity suffix is kept rather than stripped because it is what
`demangler.py` produces, so a symbol demangled during analysis and a name from
this library spell one class one way. Stripping it would not help the metric
either: `TList` still does not match `TList<System`.

## What this cannot recover

* **Constructors**, for the reason above.
* **Anything without external linkage**: implementation-section procedures,
  nested procedures, closure bodies.
* **Releases whose packages one does not have.** This is the binding
  constraint, and it is not a technical one. Nobody publishes Delphi runtime
  packages on their own; they arrive bundled with an application that links
  against them, so which releases this pipeline can cover is decided by what
  somebody happened to redistribute. `rtl270.bpl`, `vcl270.bpl` and
  `vclimg270.bpl` — 10.4 Sydney — came out of the binary distribution of
  [ArchaeoMag](https://github.com/antonio-schettino/ArchaeoMag), a freely
  downloadable academic program. No comparable public bundle was found for
  Delphi 11, 12 or 13. Note that redistributed packages remain Embarcadero's,
  under Embarcadero's terms, whatever the bundling application's licence says.

Against [RTTI.md](RTTI.md)'s list, though, it recovers two of the three things
that pipeline cannot: unit-level procedures, and prototypes. Private and
protected methods stay out of reach, because they have no external linkage
either.

## Usage

The packages themselves are inputs rather than deliverables, and are not ours
to redistribute. What this builds from them is: a `.warp` holds fingerprints
and names, not code. So the packages live beside the other fetched binaries in
`corpus/borlandrtl/`, which `.gitignore` already covers, and only the generated
library is committed.

    python3 tools/build_bpl.py <tag> <package.bpl> [more.bpl ...]
                               [--out DIR] [--no-exclude-shipped]
                               [--no-prototypes]

    python3 tools/bpleval.py <package.bpl> <library.warp>

    # 10.4 Sydney, as shipped:
    python3 tools/build_bpl.py 10.4 corpus/borlandrtl/rtl270.bpl \
                               corpus/borlandrtl/vcl270.bpl \
                               corpus/borlandrtl/vclimg270.bpl

Every package of one release goes into one library: they are one RTL split over
several files, and a body that appears in two of them has to be recognised as
one body rather than two.

## Modules

| File | Contents |
| --- | --- |
| `tools/bplkb.py` | Package reader: exports, `PACKAGEINFO`, the naming rules |
| `tools/bplgen.py` | Analysis, prototypes, the GUID rules, `.warp` generation |
| `tools/build_bpl.py` | End to end, with the shipped-GUID exclusion |
| `tools/bpleval.py` | A package's export names against an independent library |
