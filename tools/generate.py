"""Build a WARP signature library from an IDR knowledge base.

Everything goes into one image.  Batching looked attractive until the numbers
came in: relinking fixups is worth 3.5x the match rate, a call crossing a batch
boundary cannot be relinked, and the RTL is densely interconnected -- the median
module's dependency closure is 7181 of 41467 procedures.  Pinning the core
(the 16 modules used by more than half of all units, 5073 procedures) into every
batch costs exactly as much as analysing everything at once and still loses
cross-batch calls, so the single image wins outright.

The analysed image is saved as a database.  That is the expensive artifact --
regenerating the library with different inclusion rules afterwards costs
seconds, so decisions about which procedures deserve signatures stay reversible.
"""

import os
import time

import binaryninja as bn
from binaryninja import Symbol, SymbolType, warp

from . import classes as dclasses
from . import kb as kbmod
from . import naming
from . import stage
from . import delphitypes as dtypes

SELECTED_TAG = "WARP: Selected Function"

# A dump this large is not a function anyone wants a signature for -- the one
# offender in Delphi 7 is MidasLib.DllGetDataSnapClassObject at 165 KB, which
# is effectively all of midas.dll in a single procedure and which Binary Ninja
# then analyses as a body spanning 1.6 MB.
MAX_DUMP = 0x10000


def display_units(kb):
    """Proper-cased unit names: the DCU filename keeps the case, the unit
    record sometimes does not."""
    out = {}
    for i in range(kb.sections['modules'][0]):
        m = kb.module(i)
        out[m['id']] = os.path.splitext(m['filename'])[0] or m['name']
    return out


def build_view(kbpath, imgpath, modules=None, log=print):
    kb = kbmod.KB(kbpath)
    units = display_units(kb)
    t = time.time()
    layout = stage.Layout(kb, modules=modules)
    relinked, unresolved = layout.render(imgpath)
    log("staged %d procs, %d fixups relinked, %d unresolved (%.1fs)"
        % (len(layout.procs), relinked, unresolved, time.time() - t))

    t = time.time()
    bv = bn.load(imgpath, update_analysis=False, options={
        "loader.architecture": "x86",
        "loader.platform": "windows-x86",
        "loader.imageBase": stage.BASE})
    for addr, _ in layout.procs:
        bv.create_user_function(addr)
    bv.update_analysis_and_wait()
    log("analysed %d functions (%.1f min)"
        % (len(list(bv.functions)), (time.time() - t) / 60))

    try:
        bv.create_tag_type(SELECTED_TAG, "\u2713")
    except Exception:
        pass
    tmap = dtypes.TypeMap(bv)
    index = dclasses.ClassIndex(kb, tmap)
    defined = index.define_all(bv)
    log("defined %d class layouts from the knowledge base" % defined)
    named = thunks = typed = oversize = 0
    for addr, p in layout.procs:
        func = bv.get_function_at(addr)
        if func is None:
            continue
        # Contribution is decided here rather than at staging, so the analysed
        # database stays complete and the decision can be revisited by
        # regenerating rather than re-analysing. Degenerate stubs carry no
        # identifying content -- they only ever produce ambiguity declines --
        # and they dominate the collision groups the matcher has to score.
        if stage.is_thunk(p['code']):
            thunks += 1
            continue
        if len(p['code']) > MAX_DUMP:
            oversize += 1
            continue
        bv.define_user_symbol(Symbol(
            SymbolType.FunctionSymbol, addr,
            naming.proc_name(units.get(p['module_id']), p['name'])))
        # The processor contributes tagged functions only, so this is what
        # actually decides inclusion -- naming alone is not enough.
        func.add_tag(SELECTED_TAG, "")
        named += 1
        # WARP only carries a type when the function has a user-defined one,
        # so this is what puts prototypes into the signature library.
        if p['args'] or p['typedef']:
            try:
                # set_user_type, not `function_type =`: WARP only carries a
                # type when has_user_type() is true, and the plain assignment
                # does not set that flag.
                func.set_user_type(tmap.function_type(p, index))
                typed += 1
            except Exception:
                pass
    # Symbols land immediately, but user types do not: until analysis runs
    # again func.type still reports the inferred signature, and that stale
    # type is what WARP would serialise.
    if typed:
        t = time.time()
        bv.update_analysis_and_wait()
        log("committed prototypes (%.1f min)" % ((time.time() - t) / 60))
    log("named %d functions, %d with prototypes (skipped %d thunks, %d oversize)"
        % (named, typed, thunks, oversize))
    return bv, layout


def select_contributed(bv, log=print):
    """Tag exactly the functions that should become signatures.

    Removing a symbol is not enough to exclude a function: Binary Ninja
    re-names a bare jump thunk after its target, so a stripped thunk comes
    back as an auto-annotated `j_Unit::Member` and is contributed anyway --
    which is how a filtering pass ended up producing a *larger* library than
    the one it was meant to shrink. Tagging is the mechanism that actually
    decides inclusion, paired with IncludedFunctionsSelected.
    """
    try:
        tag_type = bv.create_tag_type(SELECTED_TAG, "\u2713")
    except Exception:
        tag_type = bv.tag_types.get(SELECTED_TAG)
    selected = skipped = 0
    for func in list(bv.functions):
        sym = func.symbol
        if sym is None or sym.auto or "::" not in sym.name:
            skipped += 1
            continue
        size = max(r.end for r in func.address_ranges) - func.start
        if size > MAX_DUMP or stage.is_thunk(bv.read(func.start, min(size, 8))):
            skipped += 1
            continue
        func.add_tag(SELECTED_TAG, "")
        selected += 1
    log("selected %d functions, skipped %d" % (selected, skipped))
    return selected


def generate(kbpath, workdir, outfile, modules=None, save_db=True, log=print):
    os.makedirs(workdir, exist_ok=True)
    img = os.path.join(workdir, "image.bin")
    dbf = os.path.join(workdir, "image.bndb")
    t0 = time.time()

    if save_db and os.path.exists(dbf):
        log("reusing analysed database %s" % dbf)
        bv = bn.load(dbf, update_analysis=False)
        # The database was named before the contribution filter existed, so
        # apply it here too. Sizes come from the analysed functions themselves,
        # which is the same measure the matcher uses.
        select_contributed(bv, log)
    else:
        bv, _ = build_view(kbpath, img, modules, log)
        if save_db:
            bv.create_database(dbf)
            log("saved %s" % dbf)

    t = time.time()
    proc = warp.WarpProcessor(
        included_functions=warp.warp_enums.WARPProcessorIncludedFunctions
        .WARPProcessorIncludedFunctionsSelected)
    proc.add_binary_view(bv)
    wf = proc.start()
    if wf is None:
        raise RuntimeError("WARP processor produced nothing")
    open(outfile, "wb").write(bytes(wf.to_data_buffer()))
    log("wrote %s: %d functions, %d bytes (warp %.1fs, total %.1f min)"
        % (outfile, sum(len(c.functions) for c in wf.chunks),
           os.path.getsize(outfile), time.time() - t, (time.time() - t0) / 60))
    return outfile
