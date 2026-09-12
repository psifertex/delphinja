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

import os
import sys
import time

import binaryninja as bn
from binaryninja import Symbol, SymbolType, warp

from . import fpcname
from . import fpcstage
from . import fpctypes
from . import repro

SELECTED_TAG = "WARP: Selected Function"

# Same ceiling as the Delphi side: a dump this large is not a function anyone
# wants a signature for.
MAX_DUMP = 0x10000

STAMP_VERSION = 2


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


TOOL_FILES = (__file__, fpcstage.__file__, fpcname.__file__, fpctypes.__file__,
              os.path.join(os.path.dirname(__file__), "coff.py"))


def build_identity(paths, platform, source=None):
    """Content-address every code/case input and build-affecting setting."""
    companion = [os.path.splitext(path)[0] + ".ppu" for path in paths]
    inputs = {"objects_and_ppus": repro.file_inventory(
        list(paths) + [path for path in companion if os.path.isfile(path)])}
    if source is not None:
        inputs["source"] = source
    return repro.build_manifest(
        "fpc-warp", inputs,
        {"max_dump": MAX_DUMP, "platform": platform,
         "selected_tag": SELECTED_TAG, "stamp_version": STAMP_VERSION},
        repro.file_inventory(TOOL_FILES, os.path.dirname(__file__)),
        {"binary_ninja": bn.core_version(),
         "python": "%d.%d.%d" % sys.version_info[:3]})


def _stamp(paths, platform="windows-x86", source=None):
    """Compatibility name for callers that inspect the analysed-image key."""
    return repro.manifest_stamp(build_identity(paths, platform, source))


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
    if bv is None:
        raise RuntimeError("Binary Ninja could not open %s" % imgpath)
    try:
        return _configure_view(bv, layout, oracle, log, t)
    except BaseException:
        bv.file.close()
        raise


def _configure_view(bv, layout, oracle, log, started):
    for addr, _ in layout.procs:
        bv.create_user_function(addr)
    bv.update_analysis_and_wait()
    log("analysed %d functions (%.1f min)"
        % (len(list(bv.functions)), (time.time() - started) / 60))

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
             log=print, source=None):
    os.makedirs(workdir, exist_ok=True)
    img = os.path.join(workdir, "image.bin")
    dbf = os.path.join(workdir, "image.bndb")
    stampf = os.path.join(workdir, "stamp.json")
    t0 = time.time()

    paths = object_files(roots)
    if not paths:
        raise RuntimeError("no object files under %s" % (roots,))
    build = build_identity(paths, platform, source)

    cached = repro.read_cache(stampf, build) if save_db else None
    database = cached.get("database") if isinstance(cached, dict) else None
    if database and repro.verify_file(dbf, database):
        # Only a database built from these exact inputs by this exact code is
        # reusable: build_view is where types and conventions are applied, and
        # it is skipped entirely on this path.
        log("reusing analysed database %s" % dbf)
        bv = bn.load(dbf, update_analysis=False)
        rebuilt = False
    else:
        if os.path.exists(dbf) or os.path.exists(stampf):
            log("cached database is stale or corrupt, rebuilding")
        oracle = case_oracle(paths, log)
        bv, _ = build_view(paths, img, platform, oracle, log)
        rebuilt = True
    if bv is None:
        raise RuntimeError("Binary Ninja could not open %s" % dbf)
    try:
        if rebuilt and save_db:
            bv.create_database(dbf)
            repro.write_cache(
                stampf, build,
                {"database": {"size": os.path.getsize(dbf),
                              "sha256": repro.file_hash(dbf)},
                 "objects": len(paths)})
            log("saved %s" % dbf)
        return _write_warp(bv, outfile, build, t0, log)
    finally:
        bv.file.close()


def _write_warp(bv, outfile, build, started, log):
    t = time.time()
    proc = warp.WarpProcessor(
        included_functions=warp.warp_enums.WARPProcessorIncludedFunctions
        .WARPProcessorIncludedFunctionsSelected)
    proc.add_binary_view(bv)
    wf = proc.start()
    if wf is None:
        raise RuntimeError("WARP processor produced nothing")
    with repro.atomic_path(outfile) as temporary:
        with open(temporary, "wb") as fh:
            fh.write(bytes(wf.to_data_buffer()))
    repro.write_artifact_manifest(outfile, build)
    log("wrote %s: %d functions, %d bytes (warp %.1fs, total %.1f min)"
        % (outfile, sum(len(c.functions) for c in wf.chunks),
           os.path.getsize(outfile), time.time() - t,
           (time.time() - started) / 60))
    return outfile
