# Free Pascal signature libraries

The FPC half of `tools/`. The Delphi pipeline and this one are the same four
steps — stage, relink, analyse, generate — differing only in where the
(name, bytes, relocations, prototype) quadruple comes from.

## Where the names come from

A Free Pascal release ships its compiled RTL as `.o` object files next to the
`.ppu` metadata, and **that is the knowledge base**. Three facts make it work:

1. **A `.ppu` holds no machine code.** `compiler/entfile.pas` enumerates every
   entry a PPU can carry and there is no code entry; the link entries are
   containers of *file names*. The bytes live in the companion `.o`.
2. **On Windows every routine gets its own section.**
   `compiler/systems/i_win.pas` sets `tf_smartlink_sections` for win32 and
   win64, `ogcoff.pas` sets `af_smartlink_sections` for both PECOFF writers,
   and `hlcgobj.pas` opens `new_section(..., sec_code, lower(pd.mangledname))`
   for *every* procdef — public or not, with or without `-CX`. The assembler
   writer prefixes `.n_`, giving `.text.n_<lowercased mangled name>`.
3. **So a shipped object gives exact bytes, exact extents and an
   authoritative relocation table per routine** — the same triple an IDR
   knowledge base gives for Delphi, with the relocations *read* rather than
   reconstructed.

FPC 3.2.2 win32 ships 9,279 routines and 911 KB of code across the `rtl*`
packages. No compiler installation is needed: the Windows installers are Inno
Setup archives, and `innoextract` unpacks them anywhere.

## Demangling

`compiler/symdef.pas` is authoritative; the published documentation is stale.
`make_mangledname` composes

    [typeprefix + '_$'] + unitname + ['$_$' + prefix] + ['_$$_' + suffix]

with object scopes contributing `<objname>_$_` to *prefix* and nested routines
contributing `<procname><params>`, and `mangledprocparanames` appending
`'$' + <TYPE>` per parameter and `'$$' + <TYPE>` for a non-void return.

    SYSUTILS_$$_STRCOMP$PCHAR$PCHAR$$LONGINT      SysUtils::StrComp
    SYSTEM$_$TOBJECT_$__$$_DESTROY                System::TObject::Destroy

**FPC 2.6.x mangles differently** and needs its own parse: there the parts are
joined with a plain `_`, so `CLASSES_TSTREAM_$__READDWORD$$LONGWORD` is
`Classes::TStream::ReadDWord`. A `_` is also a perfectly ordinary character in
an identifier, so the only reliable boundary is the unit name — which is
recoverable, because it is the name of the object file the symbol came from,
and that is what `demangle`'s `unit` argument is for. The two schemes are told
apart by `$_$`/`_$$_`, which 2.6.x never emits.

Two things the symbol does not carry:

* **Letter case.** `symdef.pas` mangles `procsym.name`, the uppercase form,
  never `realname`. It is restored from the companion `.ppu`, read as a bag of
  identifiers rather than parsed — the PPU format is version-locked and churns
  every release, while the identifiers in it are just bytes. Per uppercased
  key the most source-looking spelling wins (mixed case beats all-lower beats
  all-upper). A wrong guess costs letter case in a name, never a wrong name.
* **Long parameter lists**, which collapse to `$crc<hex32>` in 3.2.2 and
  `$h<base64 fnv64>` on trunk. Those routines are named but carry no
  prototype: claiming an empty parameter list would be worse than claiming
  none.

## Hidden parameters

The mangled name lists only the *declared* parameters — `vo_is_hidden_para`
ones are skipped — so the ABI's hidden parameters are reconstructed from the
`paranr_*` constants in `symconst.pas`:

| Hidden parameter | When | Position |
| --- | --- | --- |
| `$parentfp` | routine nested in another (`paranr_parentfp = 2`) | first |
| `$self` | method (`paranr_self = 3`) | after `$parentfp` |
| `$vmt` | constructor or destructor (`paranr_vmt = 5`) | after `$self` |
| `$result` | `paramanager.ret_in_param` return type | **last on i386** |

`$result` would be third by `paranr_result = 4`, but `insert_funcret_para` has
an i386-only branch giving it `paranr_result_leftright` for
`pushleftright_pocalls = [pocall_register, pocall_pascal]` — so on win32 it
lands after the declared parameters and on win64 before them.

Two of these are conventions rather than facts the mangling records, and are
documented as such in `fpcname.hidden_params`: a destructor is recognised by
Object Pascal's universal `Destroy` spelling, and a constructor by a `Create*`
member returning its own class. `ret_in_param` is claimed only for return
types nameable from the symbol alone (the string types, variants, open
arrays) — a record and a class are both spelled `TFoo`, and guessing wrong
would shift every register parameter.

## Calling convention

`globtype.pas` sets `pocall_default = pocall_register` on i386 and x86_64, but
the name means different things on the two. On i386 it is the
Borland-compatible register convention Binary Ninja calls `register`, the same
one the Delphi libraries already emit, so `delphitypes.py` carries over. On x86_64
the compiler routes every convention through `x86_64_use_ms_abi` for win64
targets, so it is simply the Microsoft x64 ABI — `win64`. That also moves a
hidden parameter: `insert_funcret_para`'s `paranr_result_leftright` branch is
i386-only, so `$result` is last on win32 and third on win64.

A build **fails** rather than falls back if the core does not offer the
convention: a signature with no convention is recoverable by analysis, one
with the wrong convention is not.

## What is not recovered

* **Class layouts.** The Delphi side builds real structs from IDR type
  records; FPC's equivalent lives inside the `.ppu`, and a native reader for
  it is a version-locked project of its own. Class references therefore stay
  `void*` — `delphitypes.py`'s existing shape heuristic. `ppudump -Fj` (from a
  matching release) would supply them, and parameter names too, but it needs
  a matching-version FPC install, so nothing here depends on it.
* **Anything outside the `rtl*` packages.** The full unit tree stages 113,738
  routines: a much longer analysis and a much larger image, and WARP masks
  constants that fall inside the mapped extent, so an oversized image changes
  how functions hash. LCL is not in an FPC release at all — that is a Lazarus
  artifact and a separate library per Lazarus minor.

## Measuring

`tools/fpceval.py`. Recall is the easy number; the Delphi evaluator gets
precision from the RTTI in every Delphi binary and FPC emits no such thing, so
precision comes from the reference objects instead: read each matched function
back out of the target binary and compare it with the reference bytes,
ignoring exactly the offsets the object's relocation table marks.

That proves a match is not a collision between two different routines. It does
**not** prove the name is right — the name comes from the demangler and the
check compares code — and it says nothing about functions that should have
matched and did not.

## Measured

Against `corpus-fpc/` (41 Windows PE binaries: FPC's own tools for three
releases, the Lazarus 2.2.6 IDE tools, and six shipped applications).
"Before" is Binary Ninja's own analysis with no library registered.

| | functions | matched | rate |
| --- | ---: | ---: | ---: |
| before, whole corpus | 351,970 | 130 | 0.04% |
| after, whole corpus, `fpc-rtl-3.2.2-win32` alone | 352,028 | 21,880 | **6.2%** |

6.2% understates it, because that one library is the wrong version for 18 of
the 41 files and the wrong architecture for 4. Version-matched:

| library | corpus subset | functions | matched | rate | byte-verified |
| --- | --- | ---: | ---: | ---: | ---: |
| `fpc-rtl-2.6.4-win32` | FPC 2.6.4 tools | 14,254 | 3,445 | 24.2% | 99.5% |
| `fpc-rtl-3.0.4-win32` | FPC 3.0.4 tools | 16,636 | 4,303 | 25.9% | 99.7% |
| `fpc-rtl-3.2.2-win32` | whole corpus | 352,028 | 21,880 | 6.2% | 99.6% |
| `fpc-rtl-3.2.2-win64` | the four PE32+ files | 94,883 | 9,173 | 9.7% | 99.8% |

Per file the rate runs 30–47% on ordinary FPC programs (`ptop.exe` 40.8%,
`fpc.exe` 47.3%), 5–10% on large Lazarus/LCL applications — where most of the
code is LCL and application units that no FPC release ships — and ~7% on the
compiler itself, which is mostly compiler.

The unverified matches are a consistent handful of the same routines
(`Objects::RegisterObjects`, `Finalize::Classes`, unit init/finalize stubs):
short, near-identical bodies whose relocation tables do not cover every byte
that differs.

## Usage

    python3 tools/build_fpc.py [outdir] [workdir] [versions]
    python3 tools/fpceval.py corpus-fpc --libs signatures/fpc-rtl-3.2.2-win32.warp \
        --ref /tmp/fpc-warp-build/releases/fpc-3.2.2/app/units/i386-win32/rtl

Both put the repository root on `sys.path` and import `tools.<module>`;
importing the `delphinja` package would run the plugin's `__init__` and
register the recovery workflow inside the build process, where it would then
run against the staged image and remove functions from it.

`tools/bnenv.py` points `BN_USER_DIRECTORY` at a scratch directory and seeds
it with the licence and enterprise URL, so an unattended run neither writes to
the real configuration nor dies on the first analysis.

## Modules

| File | Contents |
| --- | --- |
| `tools/coff.py` | PE/COFF relocatable object reader (replaces `kb.py`) |
| `tools/fpcname.py` | Demangler, hidden-parameter model, `.ppu` case oracle |
| `tools/fpcstage.py` | Section layout and real relocation application |
| `tools/fpctypes.py` | FPC type names and prototypes (extends `delphitypes.py`) |
| `tools/fpcgen.py` | Analysis, naming and `.warp` generation |
| `tools/build_fpc.py` | Fetches releases and builds every target |
| `tools/fpceval.py` | Corpus evaluation with byte-level verification |
| `tools/bnenv.py` | Scratch Binary Ninja user directory (shared with `build_all.py`) |

## Version coverage

FPC 3.2.2 (May 2021) is still the current stable release, and every Lazarus
from 2.2.0 (Jan 2022) to 4.8 (Jun 2026) bundles it. One library therefore
covers most FPC binaries in the wild, with 3.0.4 and 2.6.4 for older ones —
a far smaller matrix than Delphi's.
