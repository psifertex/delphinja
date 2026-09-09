"""Read the extended RTTI out of a binary, and turn a consensus into a `.warp`.

Two halves, both needing Binary Ninja.

**Harvest.**  Analyse one binary, ask the plugin's own decoder which functions
its metadata names, and record for each the WARP function GUID.  The GUID is
the point: it is what the matcher compares, so two binaries agreeing on it are
agreeing on exactly the thing that decides a match, with relocations,
displacements and image-relative constants already masked by the same code that
will mask them at match time.  Deriving an equivalent mask by hand -- which is
what an IDR knowledge base supplies for the older libraries -- is not needed and
would not be as faithful.

The harvest runs under a scratch Binary Ninja user directory with no signature
libraries registered, so a GUID recorded here comes from analysis of the binary
alone and never from a name some other library already applied.

**Generate.**  A WARP library is produced from analysed functions in a
`BinaryView`, so the readings the consensus kept have to be pointed at as real
functions.  They already are -- in the binaries they were harvested from.  So
generation re-analyses a covering subset of those binaries, names and tags
exactly the kept functions in each, and hands every view to one
`WarpProcessor`.  Nothing is staged, relinked or synthesised: the code that
goes into the library is code as a real program links it, which is the shape
the library will meet.
"""

import json
import os
import time

import binaryninja as bn
from binaryninja import Symbol, SymbolType, warp

from . import rttikb

SELECTED_TAG = "WARP: Selected Function"


def log(message):
    """Progress for a run measured in tens of minutes, so it is flushed.

    Python block-buffers a redirected stdout, and an unattended build's log
    file staying empty for twenty minutes is indistinguishable from a hang.
    """
    print(message, flush=True)


def _metadata(bv):
    """The plugin's decoder, imported here rather than at module import.

    `tools` is imported without the `delphinja` package around it precisely so
    that a build does not register the recovery workflow into its own process;
    the decoder itself is safe, and this is the one place that wants it.
    """
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parent = os.path.dirname(root)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    from delphinja.rtti import apply as A
    return A.DelphiMetadata(bv)


def harvest(path):
    """One binary's readings: every RTTI-named function, with its WARP GUID."""
    started = time.time()
    bv = bn.load(path, update_analysis=True,
                 options={"analysis.debugInfo.internal": False})
    bv.update_analysis_and_wait()
    md = _metadata(bv).scan()

    claims = {}
    for vmt in md.vmts.values():
        unit, source = md.unit_for(vmt)
        # Both method arrays. The extended one carries all but a fraction of a
        # percent of a modern binary's names; the original one is still read so
        # that a class whose extended array is absent is not silently skipped.
        for method in vmt.methods + vmt.methods_ex:
            claims.setdefault(method["addr"], []).append(
                (unit, source, vmt.name, method["name"]))

    # A method array entry is proof of an entry point whether or not analysis
    # reached it, and an address with no function has no GUID to record.
    created = 0
    for addr in claims:
        if bv.is_valid_offset(addr) and bv.get_function_at(addr) is None:
            if bv.create_user_function(addr) is not None:
                created += 1
    if created:
        bv.update_analysis_and_wait()

    entries = []
    for addr, claim in claims.items():
        func = bv.get_function_at(addr)
        if func is None:
            continue
        try:
            guid = str(warp.WarpFunction(func).guid)
        except Exception:
            continue
        entries.append(dict(
            addr=addr, guid=guid, blocks=len(list(func.basic_blocks)),
            size=max(r.end for r in func.address_ranges) - func.start,
            claims=claim))
    return dict(file=path, functions=len(list(bv.functions)),
                claimed=len(claims), created=created, entries=entries,
                n_virtuals=getattr(getattr(md, "layout", None), "n_virtuals", None),
                seconds=round(time.time() - started, 1))


def harvest_corpus(paths, cachedir, log=log):
    """Harvest every binary, one JSON file each, skipping what is already done.

    Resumable by construction: a corpus harvest is tens of minutes of analysis
    and a crash on file thirty should not cost the first twenty-nine.
    """
    os.makedirs(cachedir, exist_ok=True)
    records = []
    for path in paths:
        key = "%s_%s.json" % (os.path.basename(os.path.dirname(path)),
                              os.path.basename(path))
        dst = os.path.join(cachedir, key)
        if os.path.exists(dst):
            records.append(json.load(open(dst)))
            continue
        record = harvest(path)
        json.dump(record, open(dst, "w"))
        log("%-42s functions=%-6d named=%-5d %.0fs"
            % (os.path.basename(path), record["functions"],
               len(record["entries"]), record["seconds"]))
        records.append(record)
    return records


def shipped_guids(paths, log=log):
    """Every function GUID the already-published libraries claim.

    Read from the `.warp` files rather than rebuilt from the knowledge bases:
    the file is what the matcher will load, and the point of the set is to keep
    this library from claiming a GUID another loaded library already claims.
    """
    guids = set()
    for path in paths:
        warp_file = warp.WarpFile(path)
        before = len(guids)
        for chunk in warp_file.chunks:
            guids.update(str(f.guid) for f in chunk.functions)
        log("%-28s %d GUIDs not already seen"
            % (os.path.basename(path), len(guids) - before))
    return guids


def _tag_type(bv):
    try:
        return bv.create_tag_type(SELECTED_TAG, "✓")
    except Exception:
        return bv.tag_types.get(SELECTED_TAG)


def contribute(path, wanted, log=log):
    """Analyse `path` and tag exactly `wanted` -- {(name, guid): address}.

    The GUID is re-checked against this fresh analysis rather than trusted from
    the harvest.  It should always agree, since nothing about the analysis has
    changed; checking costs nothing and turns a silent drift into a number.
    """
    bv = bn.load(path, update_analysis=True,
                 options={"analysis.debugInfo.internal": False})
    bv.update_analysis_and_wait()
    created = 0
    for _, addr in wanted.items():
        if bv.get_function_at(addr) is None and bv.is_valid_offset(addr):
            if bv.create_user_function(addr) is not None:
                created += 1
    if created:
        bv.update_analysis_and_wait()
    _tag_type(bv)
    tagged = drifted = missing = 0
    for (name, guid), addr in wanted.items():
        func = bv.get_function_at(addr)
        if func is None:
            missing += 1
            continue
        if str(warp.WarpFunction(func).guid) != guid:
            drifted += 1
            continue
        bv.define_user_symbol(
            Symbol(SymbolType.FunctionSymbol, addr, name))
        func.add_tag(SELECTED_TAG, "")
        tagged += 1
    log("%-42s tagged=%-6d drifted=%-4d missing=%d"
        % (os.path.basename(path), tagged, drifted, missing))
    return bv, dict(tagged=tagged, drifted=drifted, missing=missing)


def generate(keep, outfile, limit=None, log=log):
    """Build `outfile` from the binaries that between them hold `keep`."""
    chosen, remaining = rttikb.cover(keep, limit)
    log("cover: %d binaries hold %d of %d readings"
        % (len(chosen), len(keep) - len(remaining), len(keep)))
    processor = warp.WarpProcessor(
        included_functions=warp.warp_enums.WARPProcessorIncludedFunctions
        .WARPProcessorIncludedFunctionsSelected)
    # The views are kept alive until start() returns: the processor reads them
    # then, not when they are added.
    views = []
    totals = dict(tagged=0, drifted=0, missing=0)
    for path, wanted in chosen:
        bv, stats = contribute(path, wanted, log)
        for k in totals:
            totals[k] += stats[k]
        processor.add_binary_view(bv)
        views.append(bv)
    started = time.time()
    warp_file = processor.start()
    if warp_file is None:
        raise RuntimeError("WARP processor produced nothing")
    open(outfile, "wb").write(bytes(warp_file.to_data_buffer()))
    log("wrote %s: %d functions, %d bytes (%.0fs)"
        % (outfile, sum(len(c.functions) for c in warp_file.chunks),
           os.path.getsize(outfile), time.time() - started))
    return outfile, totals
