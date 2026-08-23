# Signature libraries

How the `.warp` files in `../signatures` are built. Nothing here is imported
when the plugin loads; it is the offline toolchain, kept with the plugin so
the libraries can be rebuilt and audited rather than taken on trust.

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

## Free Pascal

Everything above is the Delphi pipeline. Free Pascal binaries are built from
the same four steps against a different source — a shipped FPC release's `.o`
files rather than an IDR knowledge base — and that half lives in
[FPC.md](FPC.md), with its own modules (`coff.py`, `fpcname.py`, `fpcstage.py`,
`fpctypes.py`, `fpcgen.py`, `build_fpc.py`, `fpceval.py`). `types.py`,
`naming.py` and `bnenv.py` are shared.

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
| `tools/bnenv.py` | Scratch Binary Ninja user directory for batch runs |

## Attribution

Knowledge base data ©crypto2011, MIT licensed. 
