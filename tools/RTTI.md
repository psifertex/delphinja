# The post-XE6 signature library

The third source in `tools/`, after IDR knowledge bases ([README.md](README.md))
and Free Pascal object files ([FPC.md](FPC.md)). Those two start from an
artifact somebody ships; this one does not, because for Delphi 10 Seattle
onwards nobody ships one.

## Why there is a gap at all

Every `delphi-rtl-*.warp` up to `2014` comes from an IDR knowledge base, and
IDR's published knowledge bases stop at XE6 (2014). Nothing else publishes the
compiled RTL: a `.dcu` exists only inside a Delphi installation, and the
runtime packages that do get redistributed (`rtl*.bpl`, `vcl*.bpl`) ship with
applications rather than on their own. So Delphi 10.x, 11, 12 and 13 have no
library, and what goes unnamed in a modern binary is exactly the RTL.

## What a modern binary says about itself

Since Delphi 2010 the compiler emits an extended method array beside every
VMT, holding the name and address of each public and published method of the
class — including the RTL's own classes, because the binary links them. A
Delphi 12 executable therefore states, in its own metadata, that the function
at some address is `System.Classes.TStrings.AddStrings`. delphinja already
reads that array; this pipeline treats it as a *knowledge base per binary*.

One binary's reading is not evidence enough. What makes it evidence is that
the same routine can be read out of many unrelated programs and the readings
compared.

## The rule

A reading is a (name, GUID) pair, where the GUID is WARP's own function GUID.
That is deliberate: it is the equivalence the matcher compares, computed by the
code that will compare it, with relocations, call displacements and
image-relative constants already masked. Nothing here reconstructs a relocation
mask, and nothing needs to.

A pair is kept only when all of these hold.

| Rule | Why |
| --- | --- |
| the unit is namespaced and Embarcadero's (`System.*`, `Vcl.*`, …) | a library called `delphi-rtl` should hold the RTL, and an application may have a unit called `Classes` |
| the unit came from a `tkClass` record, not from a neighbouring one | a guessed unit is good enough to read one binary, not to decide what is RTL |
| no other name claims that address in the same binary | two names on one body is the linker folding two methods, so it is evidence against both |
| the body has at least two basic blocks | a one-block getter carries nothing that identifies it |
| **at least three independent projects produce the pair** | corroboration is the whole design |
| **no other name claims that GUID anywhere in the harvest** | that is what a collision looks like from the inside, and there is no telling which name was meant |
| **no already-shipped library claims that GUID** | see below |

Votes are counted per corpus *project*, not per file: the corpus holds an
application beside its own installer, and two releases of the same program, and
those are one piece of evidence rather than three.

### Why the shipped GUIDs are excluded

A library is selected by VMT era, and Delphi has not changed the standard
virtual count since 2009 — so this library is loaded beside `delphi-rtl-2009`
through `2014` for every Unicode-era binary. Two loaded libraries claiming one
GUID under two different names is an ambiguity the matcher resolves by
declining the match, which would cost a match the older library was already
making. Where the two agree the entry is merely redundant, and the older one
carries a prototype as well as a name.

So the whole overlap goes. It is also the measurement that says the rest is
sound: of 793 readings whose GUID an IDR-derived library also carries, **729
(91.9%) had the identical name** — two knowledge bases built from unrelated
inputs, Delphi's shipped `.dcu` files and applications' own metadata, agreeing
on the name of the same code. Most of the 64 that differ are era spellings of
one method (`CLASSES::TOwnedCollection::Create` against
`System.Classes::TOwnedCollection::Create`); the rest are bodies too generic to
identify, an empty constructor or a one-line accessor that two unrelated
classes share.

## Naming

`System.Classes::TStrings::AddStrings` — `naming.qualify`, with the unit's dots
left alone. That is not cosmetic: from XE2 the RTL's `.dcu` files are named for
the namespaced unit, so the shipped `delphi-rtl-2011`..`2014` libraries already
spell it that way, and two libraries describing one function have to produce
one string.

## What this cannot recover

* **Unit-level procedures.** Extended RTTI describes classes. A bare
  `procedure` in `System.SysUtils` has no metadata and cannot be reached.
* **Private and protected methods.** The RTL compiles with the default
  `{$RTTI EXPLICIT METHODS([vcPublic, vcPublished])}`, so a private virtual is
  in the VMT but not in the method array.
* **Prototypes.** Functions here are named but untyped.

Those three are precisely what an IDR knowledge base gives and this cannot, and
they are most of what a modern binary leaves unnamed. This library narrows the
gap; it does not close it.

## Measured

Corpus: the 32 files of `corpus/` that carry namespaced RTL classes, one per
project, spanning CompilerVersion 30.0 (10 Seattle) to 37.0 (13 Florence).

| | |
| --- | ---: |
| candidate (name, GUID) pairs | 21,674 |
| corroborated by ≥3 projects | 6,984 |
| dropped: GUID claimed by another name | 4,024 |
| dropped: GUID already shipped | 793 |
| **kept** | **2,167** (1,162 distinct names) |
| in the library after re-analysis | 2,156 |
| file size | 370 KB |

Nine binaries hold all 2,167 readings between them, which is what the library
is generated from.

### Precision

Held out, by project: for each of the fifteen binaries with a full GUID dump,
the consensus was rebuilt with that binary's own project removed, so the
library under test had never seen it. Across the fifteen, **4,942 functions
matched, and 4,936 of them carried exactly the name the target binary states in
its own metadata — 99.88%.**

The six that differ are all the same failure: two RTL routines whose bodies are
byte-identical, so WARP cannot tell them apart, and the consensus picked the
sibling. `System.Win.Registry::TRegistry::ReadInt64` for `ReadUInt64`,
`Vcl.ExtCtrls::TImage::Destroy` for `TSplitter::Destroy`, one
`TDictionary<…>::TryGetValue` instantiation for another. All six name a real
routine in the right unit; none is nonsense.

**None of the six is in the shipped library.** They exist only in the held-out
builds: the second name that disqualifies each GUID came from the very project
that was held out, and with all 32 projects voting the GUID-uniqueness rule
removes every one of them. So 99.88% is a floor, and it is the number a
sixteenth, unseen binary should expect rather than what this build ships.

The second, independent check is against the IDR-derived libraries, whose names
come from Delphi's own `.dcu` files: 793 readings share a GUID with one of
them, and 729 (91.9%) carry the identical name. That whole overlap is dropped
regardless, for the reason above.

`tools/evaluate.py` scores the same ten binaries as the recall table below,
comparing every WARP name against the target's own RTTI:

| | overlapping names | agreeing | |
| --- | ---: | ---: | ---: |
| without this library | 4,616 | 3,555 | 77.0% |
| with it | 7,081 | 5,922 | **83.6%** |

Both the coverage and the agreement rate go up, which is the shape a purely
additive library should have. Its residual disagreements are dominated by the
older libraries, and some are the metric rather than the name: `evaluate.py`
splits the RTTI name at its first `.`, so a nested class or a generic argument
list makes it compare `TFormStyleHook` or `TPropSet<System` against a name that
is in fact exactly right.

### Recall

The library names what a binary's own RTTI would have named. So it adds
nothing to a binary with rich RTTI, and a few hundred names to one whose RTTI
is thin — which is common, because a program that links few RTL classes still
links the RTL's code.

Each figure below is one binary in one process, before and after, because the
plugin registers libraries once per process and never unregisters: analysing a
Delphi 12 binary and then a Delphi 5 one in the same process leaves the modern
libraries loaded for the second, and the counts move.

| sample | Delphi | named before | named after | WARP before | WARP after |
| --- | --- | ---: | ---: | ---: | ---: |
| `Magicmida.exe` | 12 Athens | 3,884 | 4,230 | 1,343 | 2,028 |
| `BatteryMode32.exe` | 11 Alexandria | 7,635 | 7,965 | 1,936 | 2,593 |
| `Linkbar.exe` | 10.3 Rio | 5,918 | 6,210 | 2,174 | 2,764 |
| `ImageWriterSvc.exe` | 12 Athens | 7,599 | 7,600 | 1,501 | 2,504 |
| `DX.HttpDiag-Win32.exe` | 13 Florence | 5,218 | 5,219 | 851 | 1,326 |
| `TestActiveDirectory.exe` | XE2 | 9,381 | 9,381 | 3,642 | 3,807 |
| `MiniPing.exe` | 10.1 Berlin | 462 | 462 | 313 | 318 |
| `Launcher.exe` | 7 | 4,734 | 4,735 | 3,242 | 3,243 |
| `Demo.exe` | 5 | 4,974 | 6,058 | 4,194 | 4,195 |
| `Compil32.exe` | 3.02 | 2,499 | 2,498 | 1,740 | 1,739 |

The three pre-Unicode binaries are the regression set, and they cannot load
this library at all: `signatures.delphi_tags` answers `['2005', '2006', '2007',
'4', '5', '6', '7']` for the two eight-virtual binaries and `['3']` for
`Compil32.exe`. Their WARP counts move by one, which is the run-to-run spread.
`Demo.exe`'s named count is not: delphinja's own RTTI naming on the pre-Unicode
binaries is bimodal between runs, by around 700-1,100 names, with or without
this library — `Demo.exe` was measured at both 6,057 and 4,974 with no library
present. That is a pre-existing instability in the recovery pass, unrelated to
anything here and not diagnosed.

## Usage

    python3 tools/build_rtti.py [workdir] [--votes N] [--blocks N]
                                [--hold-out SUBSTRING] [--only-harvest]

The harvest caches one JSON per binary under `workdir/kb`, so changing the
consensus rules and rebuilding costs seconds rather than the hour the harvest
takes. Its key covers the binary's path relative to the corpus, its full
content hash, the decoder/harvester code, analysis options, and Binary Ninja
runtime. Thus two projects with the same executable basename cannot collide,
and changed binaries or tools cannot reuse stale readings. Cache JSON is
written atomically and malformed or mismatched records are rebuilt.
`--hold-out` is how the precision figure above is produced.

The generated library has a canonical `.manifest.json` sidecar recording the
corpus and shipped-library hashes, consensus and view settings, exact kept
reading-set digest, selected source binaries, tool hashes, runtime, and output
digest.

## Modules

| File | Contents |
| --- | --- |
| `tools/rttikb.py` | The consensus: naming, the RTL namespace list, voting, set cover |
| `tools/rttigen.py` | Harvest, shipped-GUID reader, `.warp` generation |
| `tools/build_rtti.py` | End to end, with the corpus filter and the tag |
