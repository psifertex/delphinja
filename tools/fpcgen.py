"""Build a WARP signature library from shipped Free Pascal object files.

The shape is `generate.py`'s: stage everything into one image, link it, analyse
it once, name and type every routine, then let `WarpProcessor` serialise the
tagged ones.  The saved database is the expensive artifact, so it is kept and
the library can be regenerated from it in seconds.

Where this differs from the Delphi pipeline:

* the source is a directory of `.o` files rather than an IDR knowledge base,
  and the relocation data is real rather than reconstructed;
* names are demangled from the symbol (`fpcname`) and re-cased from the
  companion `.ppu` (`fpcname.CaseOracle`);
* there is no class index -- FPC ships no type records outside the `.ppu`, so
  class references stay `void*`.

A cached database is keyed by a stamp covering the inputs *and* this file, and
is rebuilt when either changes.  Reusing a stale database silently skips
`build_view`, which is where types and calling conventions are applied, and
then produces signatures from analysis that never saw them.
"""

import hashlib
import json
import os
import time

import binaryninja as bn
from binaryninja import Symbol, SymbolType, warp

from . import fpcname
from . import fpcstage
from . import fpctypes

SELECTED_TAG = "WARP: Selected Function"

# Same ceiling as the Delphi side: a dump this large is not a function anyone
# wants a signature for.
MAX_DUMP = 0x10000

STAMP_VERSION = 1


def object_files(roots):
    """Every `.o` under the given directories, in a stable order."""
    out = []
    for root in roots:
        if os.path.isfile(root):
            out.append(root)
            continue
        for base, _dirs, names in os.walk(root):
            for n in sorted(names):
                if n.endswith(".o"):
                    out.append(os.path.join(base, n))
    return sorted(set(out))


def case_oracle(paths, log=print):
    """Source spelling for uppercased identifiers, from the `.ppu` beside
    each object.  Optional: without it names are simply upper case."""
    oracle = fpcname.CaseOracle()
    found = 0
    for path in paths:
        ppu = os.path.splitext(path)[0] + ".ppu"
        if os.path.exists(ppu):
            oracle.add_file(ppu)
            found += 1
    log("case oracle: %d identifiers from %d .ppu files" % (len(oracle), found))
    return oracle


def _stamp(paths):
    h = hashlib.sha256()
    h.update(b"fpcgen %d\n" % STAMP_VERSION)
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        h.update(("%s %d\n" % (os.path.basename(p), st.st_size)).encode())
    for mod in (__file__,
                os.path.join(os.path.dirname(__file__), "fpcstage.py"),
                os.path.join(os.path.dirname(__file__), "fpcname.py"),
                os.path.join(os.path.dirname(__file__), "fpctypes.py"),
                os.path.join(os.path.dirname(__file__), "coff.py")):
        try:
            with open(mod, "rb") as fh:
                h.update(hashlib.sha256(fh.read()).digest())
        except OSError:
            pass
    return h.hexdigest()


def build_view(paths, imgpath, platform, oracle=None, log=print):
    t = time.time()
    layout = fpcstage.Layout(paths, log=log)
    applied, skipped = layout.render(imgpath)
    log("staged %s; %d relocations applied, %d skipped (%.1fs)"
        % (layout.summary(), applied, skipped, time.time() - t))

    t = time.time()
    bv = bn.load(imgpath, update_analysis=False, options={
        "loader.architecture": "x86_64" if layout.bits == 64 else "x86",
        "loader.platform": platform,
        "loader.imageBase": fpcstage.BASE})
    for addr, _ in layout.procs:
        bv.create_user_function(addr)
    bv.update_analysis_and_wait()
    log("analysed %d functions (%.1f min)"
        % (len(list(bv.functions)), (time.time() - t) / 60))

    try:
        bv.create_tag_type(SELECTED_TAG, "✓")
    except Exception:
        pass
    tmap = fpctypes.FpcTypeMap(bv)
    if tmap.convention() is None:
        raise RuntimeError(
            "this Binary Ninja has no %r calling convention for %s; a library "
            "built without it would carry no FPC prototypes at all"
            % (fpctypes.CONVENTIONS.get(bv.arch.name), bv.arch.name))

    named = thunks = typed = oversize = unnamed = 0
    for addr, p in layout.procs:
        func = bv.get_function_at(addr)
        if func is None:
            continue
        if fpcstage.is_thunk(p["code"]):
            thunks += 1
            continue
        if p["size"] > MAX_DUMP:
            oversize += 1
            continue
        name = fpcname.demangle(p["name"], p["unit"])
        text = name.qualified(oracle)
        if not text:
            unnamed += 1
            continue
        bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, text))
        func.add_tag(SELECTED_TAG, "")
        named += 1
        ftype = tmap.function_type(name)
        if ftype is not None:
            try:
                # set_user_type, not `function_type =`: WARP only carries a
                # type when has_user_type() is true.
                func.set_user_type(ftype)
                typed += 1
            except Exception:
                pass
    if typed:
        t = time.time()
        bv.update_analysis_and_wait()
        log("committed prototypes (%.1f min)" % ((time.time() - t) / 60))
    log("named %d functions, %d with prototypes (skipped %d thunks, "
        "%d oversize, %d unnamed)"
        % (named, typed, thunks, oversize, unnamed))
    return bv, layout


def generate(roots, workdir, outfile, platform="windows-x86", save_db=True,
             log=print):
    os.makedirs(workdir, exist_ok=True)
    img = os.path.join(workdir, "image.bin")
    dbf = os.path.join(workdir, "image.bndb")
    stampf = os.path.join(workdir, "stamp.json")
    t0 = time.time()

    paths = object_files(roots)
    if not paths:
        raise RuntimeError("no object files under %s" % (roots,))
    stamp = _stamp(paths)

    cached = None
    if save_db and os.path.exists(dbf) and os.path.exists(stampf):
        try:
            cached = json.load(open(stampf)).get("stamp")
        except Exception:
            cached = None
    if cached == stamp:
        # Only a database built from these exact inputs by this exact code is
        # reusable: build_view is where types and conventions are applied, and
        # it is skipped entirely on this path.
        log("reusing analysed database %s" % dbf)
        bv = bn.load(dbf, update_analysis=False)
    else:
        if cached is not None:
            log("cached database is stale, rebuilding")
        oracle = case_oracle(paths, log)
        bv, _ = build_view(paths, img, platform, oracle, log)
        if save_db:
            bv.create_database(dbf)
            json.dump({"stamp": stamp, "objects": len(paths)},
                      open(stampf, "w"))
            log("saved %s" % dbf)

    t = time.time()
    proc = warp.WarpProcessor(
        included_functions=warp.warp_enums.WARPProcessorIncludedFunctions
        .WARPProcessorIncludedFunctionsSelected)
    proc.add_binary_view(bv)
    wf = proc.start()
    if wf is None:
        raise RuntimeError("WARP processor produced nothing")
    with open(outfile, "wb") as fh:
        fh.write(bytes(wf.to_data_buffer()))
    log("wrote %s: %d functions, %d bytes (warp %.1fs, total %.1f min)"
        % (outfile, sum(len(c.functions) for c in wf.chunks),
           os.path.getsize(outfile), time.time() - t, (time.time() - t0) / 60))
    return outfile
