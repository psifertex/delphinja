# Coalescing the shipped libraries

The fifth step in `tools/`, and the only one that produces no signatures of its
own. Its input is the seventeen `delphi-rtl-*.warp` files the other four
pipelines produced; its output is the same signatures rearranged so that no two
libraries loaded together claim the same function GUID.

## The defect

The four builders each take one release's worth of input and know nothing about
the others. `rttigen` and `bplgen` do check their candidates against the
already-shipped libraries and drop the overlap, but the twelve IDR-derived
libraries — `2` through `2014`, which are 96% of the payload — were built in one
run each and never compared. So a routine that did not change between Delphi 4
and Delphi 2007 is signed seven times, once per release.

Measured across the seventeen shipped files:

| | |
| --- | ---: |
| entries | 775,341 |
| distinct (library, GUID) claims | 466,657 |
| distinct GUIDs | 236,186 |
| **redundancy** | **49.4%** |
| GUIDs claimed by more than one library | 92,018 |
| …of those, claimed under more than one name | 35,288 |
| GUIDs claimed under more than one name *inside one library* | 22,158 |

That last row is a separate defect with the same shape: the linker folds
identical bodies, so one GUID ends up carrying eleven different method names in
`delphi-rtl-4` alone. `rttigen` and `bplgen` already drop that case at build
time — "a folded body is evidence against both names rather than for either" —
but the IDR-derived libraries predate the rule.

## Why duplicates cost more than space

Binary Ninja's WARP matcher handles two claimants for one GUID differently
depending on where they sit.

* **Two claimants in two containers.** The ambiguity is not noticed. The
  first-enumerated container wins — and container enumeration order is a fresh
  random permutation on every process start, the signature of a randomly seeded
  hash map rather than a race. It reproduces at one worker thread.
* **Two claimants in one container.** The ambiguity *is* noticed, and the
  matcher declines rather than guessing. In a controlled test, two sources with
  513 GUIDs in common matched 513 functions under identical names and 1 under
  different names.

`integration/signatures.py` gives every library its own container, so the
seven-library Delphi 5 era is the first case. On `corpus/grid2htm/Demo.exe`
across 20 runs of the same binary against the same libraries: no two runs
produced the same `(address, name)` set, and 1,892 of 4,197 matched addresses
got a different name in different runs.

The rule that falls out of those two behaviours is narrow and useful:

> A duplicate claim is harmless when the names agree and poisonous when they do
> not.

There is no API that renames a WARP signature after the fact — a `WarpFunction`
is constructed from an analysed function or read from a file, never built from
a name — so "make the duplicates agree" is not available without rebuilding
every library from its analysed image. What *is* available is deciding which
duplicate survives, and that is what this tool does.

## What loads together

Coalescing is scoped to the set of libraries a binary can actually load at
once, which `integration/signatures.py` bounds by VMT era. Two of the four eras
hold one library and need nothing done to them:

| era | TObject virtual slots | libraries |
| --- | --- | --- |
| `2`  | 4  | `2` |
| `3`  | 5  | `3` |
| `8`  | 8  | `4`, `5`, `6`, `7`, `2005`, `2006`, `2007` |
| `11` | 11 | `2009`, `2010`, `2011`, `2012`, `2013`, `2014`, `xe2plus`, `10.4` |

A GUID shared between `5` and `2013` costs nothing at match time; no binary
loads both. A GUID shared between `5` and `2007` costs a name.

## The output

Per era:

* `delphi-rtl-core-<era>.warp` — every GUID more than one of the era's
  libraries claims, once, under one name.
* `delphi-rtl-<release>-only.warp` — what is left to that release alone.

Disjoint by construction, and `--verify` checks it rather than assuming it. The
old per-release libraries stay in `signatures/` and stay loadable, but
`DELPHI_ERAS` no longer names them, so nothing registers them.

## Which name a shared GUID keeps

The only judgement in the tool. Claims are compared after normalising away the
two things that vary between eras without the routine changing:

* the unit's **namespace prefix** — `Buttons` became `Vcl.Buttons` at XE2, and
  each library follows its own input's `.dcu` naming;
* **letter case** — IDR's older knowledge bases record `SYSUTILS`, the middle
  ones `sysutils`, the newer ones `SysUtils`.

If every claim agrees under that normalisation, the GUID is kept and the
surviving spelling wins a vote: most claims wins, ties to the newest library.
If they still disagree, the GUID is dropped from that era. Voting rather than
"prefer the era-matched name" is deliberate — within an era there *is* no
era-matched name to prefer. The whole reason `4` and `2007` load together is
that a VMT slot count cannot tell a Delphi 4 binary from a Delphi 2007 one, so
"the spelling this binary's release used" is not a question the matcher can
answer.

Classifying disagreements shows what the normalisation is absorbing and what it
is refusing to. The table below compares all seventeen libraries at once rather
than era by era, so it describes the *kinds* of disagreement in the data, not
the count of decisions any one era made — 21,946 GUIDs that more than one
library claims under more than one name, after the folded-body drop below:

| kind | GUIDs | outcome |
| --- | ---: | --- |
| namespace prefix and/or unit case only | 12,928 | vote |
| letter case only | 4,520 | vote |
| member differs (`IsStoredProp` / `IsStoredPropRTTI`) | 1,281 | **drop** |
| both differ | 1,288 | **drop** |
| `_NF__` placeholder against a real name | 1,139 | placeholder loses |
| unit differs (`Datasnap.DSHTTP` / `Datasnap.DSHTTPClient`) | 729 | **drop** |
| placeholder against a disagreement | 59 | **drop** |
| member case only | 2 | vote |

The three dropped categories are a mixture of genuine renames and of tiny
bodies — an empty `Destroy`, a one-line getter — that two unrelated routines
share, and nothing in the data distinguishes them. `rttigen` drops 4,024 GUIDs
and `bplgen` 1,429 for the same reason, and the same reasoning applies here:
precision beats recall, because a wrong RTL name propagates silently and is
worse than an unnamed function.

One more drop: **placeholders, but only as votes.** IDR names an unresolved
procedure `unit::_NF__1A2`. That is no evidence of *which* routine this is, so
it never outvotes a real name — but where it is the only name on offer it is
kept, because it still names the unit and a GUID one library claims is not
ambiguous. 2,585 of `delphi-rtl-3`'s entries are in that position.

## What to do with a folded GUID, per era

22,158 GUIDs carry more than one name inside a single shipped library: the
linker folded several routines onto one body. A vote cannot help — the names
are all correct, for different routines.

The first instinct is that this is a coin flip and should be dropped, the way
`rttigen` and `bplgen` drop it at build time. The measurement says otherwise,
and says something different per era. Scoring **only** the folded-GUID matches
of a baseline run against the binary's own RTTI:

| era | binary | folded matches correct | unfolded, same run |
| --- | --- | ---: | ---: |
| 3 | `Compil32.exe` (D3.02) | 33 / 34 — 97% | 99% |
| 8 | `Demo.exe` (D5) | 39 / 45 — 87% | 99.1% |
| 8 | `Launcher.exe` (D7) | 40 / 47 — 85% | 98.6% |
| 11 | `ImageWriterSvc.exe` (D12) | **60 / 187 — 32%** | 95.7% |

87% is not a coin flip. A folded GUID reaches the matcher as several candidate
names, and it chooses between them using the constraints stored beside each
one — the GUIDs of the functions that body calls. On the older eras those
constraints identify the routine; on the Unicode era, where the folded bodies
are mostly generic instantiations and one-line accessors, they do not.
Averaging the two into one rule would be wrong in both directions, so
`FOLDED_POLICY` is per era: **keep below eleven virtual slots, drop at and
above.**

Where a fold is kept it is kept whole rather than collapsed to one name,
because two attempts to make the choice here are much worse than leaving it to
the matcher — measured on era 8 specifically, not on the global figure:

| pick rule | `Demo.exe` | `Launcher.exe` |
| --- | ---: | ---: |
| leave it to the matcher's constraints | **39 / 45** | **40 / 47** |
| plurality over the era's libraries | 2 / 11 | 4 / 13 |
| defer to a library that did not fold it | 2 / 8 | 6 / 9 |

What coalescing removes from a kept fold is only the *spelling* duplicates.
Seven era-8 libraries offer `SYSTEM::TObject::Destroy` and
`System::TObject::Destroy` from seven containers, and which one answers depends
on enumeration order; one library with one spelling per routine offers the
matcher the same candidates and no race. Era 8's 6,618 kept folds become 29,011
entries, era 3's 631 become 2,337, era 2's 468 become 1,551.

## Measured

| | before | after |
| --- | ---: | ---: |
| Delphi libraries | 17 | 19 |
| entries | 775,341 | 264,120 |
| distinct GUIDs | 236,186 | 220,122 |
| entries carrying a prototype | 730,664 (94.2%) | 247,125 (93.6%) |
| bytes on disk | 185,878,856 | 76,813,952 |

| era | libraries | GUIDs in | claims in | core | respelled | delta | folded | dropped folded | dropped disagreement |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2`  | 1 | 7,532 | 7,532 | — | — | 7,064 | 468 → 1,551 entries | — | 0 |
| `3`  | 1 | 10,996 | 10,996 | — | — | 10,365 | 631 → 2,337 entries | — | 0 |
| `8`  | 7 | 99,937 | 176,213 | 34,687 | 6,012 | 57,697 | 6,618 → 29,011 entries | — | 935 |
| `11` | 8 | 140,080 | 271,916 | 47,812 | 13,296 | 73,596 | — | 16,865 | 1,807 |

"Respelled" is the number of core entries where the era's libraries did not all
spell the name the same way, and a vote picked one — 19,308 names that used to
be a coin flip and now are not.

### On real binaries

Five binaries, one per era where an era has one to give, five consecutive runs
of each. Match counts vary run to run for exactly the reason this tool exists,
so a single run of each would prove nothing; the spread and the number of
distinct result sets are the measurement that matters.

Three columns, because the folded-GUID policy is the one decision here with a
real cost either way: **before** is the seventeen per-release libraries,
**drop** is coalescing with folded GUIDs dropped everywhere, **per-era** is
`FOLDED_POLICY` as it ships — kept below eleven slots, dropped at and above.

| binary | era | phase | matched (5 runs) | distinct sets | names varying |
| --- | --- | --- | --- | ---: | ---: |
| `grid2htm/Demo.exe` (D5) | 8 | before | 4200 ×4, 4201 | 5 of 5 | 1,518 |
| | | drop | 3686 ×5 | 2 | 1 |
| | | **per-era** | 3926–3929 | 4 | **3** |
| `gh_delphidoom/Launcher.exe` (D7) | 8 | before | 3246, 3249 ×4 | 5 of 5 | 927 |
| | | drop | 2838 ×5 | 2 | 1 |
| | | **per-era** | 3108 ×4, 3109 | 2 | **2** |
| `innosetup/Compil32.exe` (D3.02) | 3 | before | 1741 ×3, 1742 ×2 | 3 | 1 |
| | | drop | 1609 ×5 | 1 | 0 |
| | | **per-era** | 1741 ×3, 1742 ×2 | 2 | **1** |
| `gh_imagewriter/ImageWriterSvc.exe` (D12) | 11 | before | 3304 ×5 | 5 of 5 | 798 |
| | | drop | 3359 ×5 | 1 | 0 |
| | | **per-era** | 3359 ×5 | **1** | **0** |
| `gh_dx_httpdiag/DX.HttpDiag-Win32.exe` (D13) | 11 | before | 1733 ×4, 1734 | 5 of 5 | 403 |
| | | drop | 1846 ×5 | 1 | 0 |
| | | **per-era** | 1846 ×5 | **1** | **0** |

The eleven-slot era is byte-for-byte identical under both policies, which is
the check that the per-era split does not leak: `FOLDED_POLICY` is the only
thing that differs between the two builds, and era 11 reads `drop` in both.

Keeping the folds costs a little determinism and buys a lot of recall. Demo
goes from one varying address to three and from 3,686 matches to 3,928;
Launcher from one to two and from 2,838 to 3,108; Compil32 from none to one
and from 1,609 back to the full 1,741. Against the per-release set those are
still 1,518 → 3, 927 → 2 and 1 → 1 varying addresses.

One of the varying addresses on each era-8 binary is the residue the
reproduction predicted and no library publisher can remove: a collision with
Binary Ninja's own `Bundled` container, which claims
`MultiMon::InitMultiMonStubs` as `__cfltcvt_init`. The rest are the matcher
choosing inside a kept fold, which it does not do reproducibly — measured
directly on the per-release set, where a single-library era makes 130 folded
matches stably and 1 unstably.

### Precision

Against each binary's own RTTI, by the class component, which is all a
pre-2010 binary's metadata carries:

| binary | before | drop | per-era |
| --- | ---: | ---: | ---: |
| `Demo.exe` | 495–500 / 505 (98.0–99.0%, varying by run) | 452 / 452 (100%) | **473 / 474 (99.8%)** |
| `Launcher.exe` | 392–403 / 404–405 (97.0–99.5%) | 349 / 349 (100%) | **389 / 389 (100%)** |
| `Compil32.exe` | 222 / 223 (99.6%) | 189 / 189 (100%) | **222 / 223 (99.6%)** |

The two Unicode-era binaries need the other scorer. Their RTTI names generic
instantiations in full — `TList<System.Pointer>.AddRange` — where a library
spells the instantiated class `TList__1`, so the class comparison scores every
generic as a disagreement whichever library answered. Comparing the *member*
instead:

| binary | before | drop and per-era |
| --- | ---: | ---: |
| `ImageWriterSvc.exe` | 1595 / 1614 (98.8%) | **1727 / 1739 (99.3%)** |
| `DX.HttpDiag-Win32.exe` | 847 / 856 (98.9%) | **987 / 994 (99.3%)** |

So the eleven-slot era gains matches (+1.7% and +6.5%) *and* precision: what it
mostly had was duplicate claims that cost the matcher a decision. The older
eras end up roughly where they started on recall — Demo −6.5%, Launcher −4.3%,
Compil32 ±0 — with the run-to-run variation gone.

### Where the remaining era-8 recall went

Attributing all 279 addresses `Demo.exe` still does not match:

| | |
| --- | ---: |
| folded GUID, kept, but the entry no longer matched | 161 |
| GUID dropped because the era's libraries disagreed | 80 |
| GUID kept unfolded, but the entry no longer matched | 34 |
| GUID could not be computed for that function | 4 |

The 161 are not the folded rule — those GUIDs are in the library, with the
candidate set intact. They are **copy-source provenance**. Where several of the
era's libraries spell a name identically, only one of their entries is copied,
and an entry carries the constraints of the release it was built from. Splitting
Demo's baseline folded matches by which library the surviving entry came from:

| entry copied from | still matching |
| --- | ---: |
| `delphi-rtl-5` | 64 / 67 — **96%** |
| `delphi-rtl-7` | 11 / 26 — 42% |
| `delphi-rtl-2007` | 155 / 297 — 52% |

On a Delphi 5 binary, a Delphi 5 entry almost always still matches and a 2007
entry matches half the time. The tie-break that picks the copy source prefers
the newest library, which is right for the spelling and wrong for the
constraints.

Fixing that looks straightforward: keep one entry per library wherever the
libraries agree on the name — same GUID, same name, different constraints,
which by the rule at the top of this file is a harmless duplicate rather than
an ambiguity. That was built (`--every-source`) and measured, and **it does not
work**:

| binary | one entry per name | one entry per agreeing library |
| --- | --- | --- |
| `Demo.exe` (D5) | 3926–3929, 3 names varying | 3926–3928, **7 varying**, 5 of 5 sets distinct |
| `Launcher.exe` (D7) | 3108–3109, 2 varying | 3114–3115, 2 varying |
| `Compil32.exe` (D3.02) | 1741–1742, 2 sets | 1741–1742, **3 sets** |
| `ImageWriterSvc.exe` (D12) | 3359 ×5 | **3347** ×5 |
| `DX.HttpDiag-Win32.exe` (D13) | 1846 ×5 | **1834** ×5 |

Six matches gained on one binary, twelve lost on each of two others, and the
run-to-run variation on `Demo.exe` more than doubled. 264,120 entries became
422,584 in the plan and 79,252,852 bytes on disk against 76,813,952.

Two reasons it fails, both worth recording because they are not obvious.

**The extra entries do not survive as alternatives.** The compression pass
merges entries that share a GUID and a name into one whose constraint list is
the union of theirs — five staged entries for `System::@Finalize`, each
carrying nine constraints, came back as one carrying eleven. A longer
constraint list is strictly harder to satisfy, so the merge produces one
*stricter* entry rather than several the matcher can choose between. That is
why the eleven-slot era, which this was not supposed to touch at all, lost
twelve matches on both of its binaries.

**The constraints that would have helped belong to a spelling that lost.**
Taking the 254 addresses `Demo.exe` stopped matching whose name is still
somewhere in the libraries, and asking whether the Delphi 5 library is among
those that agreed on the surviving spelling:

| | |
| --- | ---: |
| Delphi 5's spelling won, so its entry is kept | 6 |
| **Delphi 5's entry is dropped because it spells the unit differently** | **187** |
| dropped earlier as a genuine name disagreement | 61 |

`delphi-rtl-5` writes `system::@Finalize` where `6`, `7`, `2005`, `2006` and
`2007` write `System::@Finalize`, so the vote goes against it and its entry —
the only one built from the release this binary actually used — is the one
that cannot be kept. Where the libraries *do* agree on the spelling their
entries turn out to be identical anyway, which is why keeping all of them buys
nothing.

Recovering those 187 would mean keeping `system::@Finalize` and
`System::@Finalize` as two entries on one GUID in one file. That is
`--all-spellings`, and it is neither built nor shipped: it would put a second
spelling on 19,308 more GUIDs — 27,025 with more than one name against 7,717
today — and those 19,308 are precisely the addresses whose names raced between
runs in the per-release set. Merging constraints alone already took `Demo.exe`
from three varying names to seven; this would be the same bargain on twenty
times the surface.

So the recall loss on the older eras stands, and its largest remaining cause is
recorded rather than fixed.

### What is still duplicated

Coalescing is per era, so a GUID both era 8 and era 11 claim is still written
twice: 15,529 GUIDs, of which 7,530 carry different names in the two eras. That
matters only in `delphi_tags(None)` — the fallback for a binary whose layout
could not be detected, which loads everything — and it is 7,530 disagreements
where the per-release set had 35,288.

## Writing a `.warp` without analysing anything

Two API notes, because neither is obvious and both were needed here.

A container's source can be **written**, not just read.
`WarpContainer.add_source(path)` on a path that does not exist creates a
writable source; `add_functions(target, source, functions)` takes
`WarpFunction` handles, including ones read out of another file's chunks; and
`commit_source` writes the file. Name, prototype and constraints survive the
copy. That is the whole of the selection pass — no image, no analysis.

That write path stores its chunk **uncompressed**, which for this data is 3.1x
larger than the shipped files. `WarpProcessor.add_path` accepts a directory of
`.warp` files as readily as a directory of binaries, and re-emits them
deflated, so the build is two passes: stage with a container, rewrite with a
processor. One file per processor, in a directory of its own — everything under
one `add_path` lands in one output, which is exactly what must not happen to
libraries that were just separated.

## Usage

The per-release libraries are this tool's input, and `signatures/` no longer
holds them: coalescing superseded them and they were deleted. A rebuild starts
by getting them back out of git.

    mkdir per-release
    for t in 2 3 4 5 6 7 2005 2006 2007 2009 2010 2011 2012 2013 2014 \
             xe2plus 10.4; do
      git show f422a1f:signatures/delphi-rtl-$t.warp \
        > per-release/delphi-rtl-$t.warp
    done
    BN_USER_DIRECTORY=... bnpython3 tools/coalesce.py <outdir> per-release
    BN_USER_DIRECTORY=... bnpython3 tools/coalesce.py <outdir> --compress
    BN_USER_DIRECTORY=... bnpython3 tools/coalesce.py <outdir> --verify

The passes are separate processes on purpose: the first leaves nineteen
containers registered, and the second must not share a process with them.
`plan.tsv` in `<outdir>` records every decision — era, GUID, destination, name
and the libraries that agreed on it — so a disputed name can be traced back
without rerunning anything.

`--every-source` and `--all-spellings` are the two variants measured above and
rejected; they are kept so the measurement can be repeated rather than taken on
trust.
