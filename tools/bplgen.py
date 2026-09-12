"""Build a WARP signature library from Delphi runtime packages.

Where `generate.py` has to stage a knowledge base into a synthetic image and
relink every fixup before Binary Ninja can analyse it, this has nothing to
stage.  A `.bpl` is already an executable image: the code sits at the address
the linker gave it, the calls between routines are already resolved, and the
relocations are in `.reloc` for the PE loader to read.  So the whole pipeline
is load, name, tag, generate -- the four steps of README.md with steps 1 and 2
already done by the compiler.

What that leaves to decide is *which* exports become signatures.  Three rules,
in the order they cost most:

**A GUID an already-shipped library claims is dropped.**  A library is selected
by VMT era and Delphi has not changed the standard virtual count since 2009, so
this library loads beside `delphi-rtl-2009`..`2014` and `xe2plus` for every
Unicode-era binary.  Two loaded libraries claiming one GUID under two names is
an ambiguity the matcher resolves by declining, which would cost a match the
older library was already making.  `rttikb.py` reached the same conclusion for
the same reason; see [RTTI.md](RTTI.md).

**A GUID two of our own names claim is dropped.**  The linker folds identical
bodies, and a folded body is evidence against both names rather than for
either.

**A body with no distinguishing content is dropped.**  `stage.is_thunk` is the
same rule the knowledge-base pipeline applies, for the same reason: a five-byte
jump only ever produces ambiguity declines.

Prototypes come free here and nowhere else.  The mangled export name carries
the full argument list and the calling convention, and `demangler.py` already
turns that into a Binary Ninja type -- so unlike the extended-RTTI library,
this one can carry types as well as names.
"""

import os
import sys
import time

import binaryninja as bn
from binaryninja import Symbol, SymbolType, warp

from . import bplkb
from . import stage
from . import repro

SELECTED_TAG = "WARP: Selected Function"

#: Same ceiling as `generate.py`: past this a "function" is a data blob that
#: analysis walked into, and no signature wants it.
MAX_DUMP = 0x10000


def build_identity(paths, shipped, prototypes):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return repro.build_manifest(
        "delphi-bpl-warp",
        {"packages": repro.file_inventory(paths),
         "excluded_libraries": repro.file_inventory(shipped)},
        {"analysis.debugInfo.internal": False, "max_dump": MAX_DUMP,
         "prototypes": bool(prototypes), "selected_tag": SELECTED_TAG},
        repro.file_inventory(
            (__file__, bplkb.__file__, stage.__file__,
             os.path.join(root, "demangler.py")), root),
        {"binary_ninja": bn.core_version(),
         "python": "%d.%d.%d" % sys.version_info[:3]})


def log(message):
    """Progress for a run measured in tens of minutes, so it is flushed."""
    print(message, flush=True)


class _Typer(object):
    """Prototypes out of mangled names, without registering a demangler.

    `demangler.py`'s `BorlandDemangler` is a Binary Ninja `Demangler`, and
    registering one is a process-wide side effect a build has no use for.
    Its type construction is a plain method on a decoded name, though, so it
    can be driven directly.  Packages are PE32, so the pointer width is four.
    """

    WIDTH = 4

    def __init__(self):
        module = bplkb._demangler()
        self.decode = module.demangle_name
        self.demangler = module.BorlandDemangler.__new__(
            module.BorlandDemangler)
        self.demangler.synthesize_self = True

    def type_for(self, mangled):
        decoded = self.decode(mangled)
        if decoded is None:
            return None
        return self.demangler._type_for(decoded, self.WIDTH)


def _tag_type(bv):
    try:
        return bv.create_tag_type(SELECTED_TAG, "✓")
    except Exception:
        return bv.tag_types.get(SELECTED_TAG)


def candidates(path, log=log):
    """Analyse one package and return its (address, name, guid, mangled) rows.

    Analysis alone, with no library registered and nothing named yet: the GUID
    recorded here has to be the GUID the matcher will compute, so it must come
    from the code and not from anything this pipeline did to the view.
    """
    started = time.time()
    claims = bplkb.readings(path)
    bv = bn.load(path, update_analysis=True,
                 options={"analysis.debugInfo.internal": False})
    if bv is None:
        raise RuntimeError("Binary Ninja could not open %s" % path)
    try:
        return _candidates_view(path, bv, claims, started, log)
    except BaseException:
        bv.file.close()
        raise


def _candidates_view(path, bv, claims, started, log):
    bv.update_analysis_and_wait()

    rows = []
    absent = thunks = oversize = 0
    for address, reading in claims.items():
        func = bv.get_function_at(address)
        if func is None:
            absent += 1
            continue
        size = max(r.end for r in func.address_ranges) - func.start
        if size > MAX_DUMP:
            oversize += 1
            continue
        if stage.is_thunk(bv.read(func.start, min(size, 8))):
            thunks += 1
            continue
        try:
            guid = str(warp.WarpFunction(func).guid)
        except Exception:
            continue
        rows.append((address, reading.name, guid, reading.mangled))
    # The function count is the denominator of the only ratio that decides
    # whether this route is worth taking: an export table names a unit's
    # interface, and everything without external linkage is invisible to it.
    log("%-16s functions=%-6d named=%-6d usable=%-6d (%d not functions, "
        "%d thunks, %d oversize) %.0fs"
        % (os.path.basename(path), len(list(bv.functions)), len(claims),
           len(rows), absent, thunks, oversize, time.time() - started))
    return bv, rows


def select(per_package, shipped, log=log):
    """Decide the library's contents across every package at once.

    Cross-package, not per-package: `rtl270.bpl` and `vcl270.bpl` are one RTL
    split over two files, and a body that appears in both under two names is
    exactly the ambiguity this has to remove.
    """
    by_guid = {}
    for _, rows in per_package:
        for _, name, guid, _ in rows:
            by_guid.setdefault(guid, set()).add(name)
    folded = {g for g, names in by_guid.items() if len(names) > 1}
    overlap = {g for g in by_guid if g in shipped}
    keep = {g for g in by_guid if g not in folded and g not in overlap}
    log("candidate GUIDs %d: dropped %d folded onto another name, "
        "%d already shipped, kept %d"
        % (len(by_guid), len(folded), len(overlap), len(keep)))
    return keep, by_guid, overlap


def shipped_guids(paths, log=log):
    """`{guid: {name, ...}}` for every function the shipped libraries claim.

    Every name, not the first one found: sixteen libraries span Delphi 2 to
    XE6, and a body small enough to be identical across all of them is claimed
    by all of them under sixteen era spellings.  Keeping one arbitrarily --
    whichever file sorts first -- turns the agreement check below into a
    comparison against the wrong era, and reads 34.9% where the same data reads
    far higher when any library is allowed to be the one that agrees.
    """
    guids = {}
    for path in paths:
        for chunk in warp.WarpFile(path).chunks:
            for function in chunk.functions:
                guids.setdefault(str(function.guid), set()).add(function.name)
    log("%d GUIDs already claimed by %d shipped libraries"
        % (len(guids), len(paths)))
    return guids


def apply(path, bv, rows, keep, demangler, log=log):
    """Name, type and tag the kept rows in one analysed package."""
    _tag_type(bv)
    named = typed = 0
    for address, name, guid, mangled in rows:
        if guid not in keep:
            continue
        func = bv.get_function_at(address)
        if func is None:
            continue
        bv.define_user_symbol(
            Symbol(SymbolType.FunctionSymbol, address, name))
        # Tagging, not naming, is what decides inclusion: the processor
        # contributes tagged functions only.  See generate.select_contributed
        # for what goes wrong when a name is used as the filter instead.
        func.add_tag(SELECTED_TAG, "")
        named += 1
        if demangler is None:
            continue
        try:
            # set_user_type, not `function_type =`: WARP only carries a type
            # when has_user_type() is true, and the plain assignment does not
            # set that flag.  The same trap generate.py documents.
            prototype = demangler.type_for(mangled)
            if prototype is not None:
                func.set_user_type(prototype)
                typed += 1
        except Exception:
            pass
    if typed:
        # Symbols land immediately, user types do not: until analysis runs
        # again func.type still reports the inferred signature, and that stale
        # type is what WARP would serialise.
        started = time.time()
        bv.update_analysis_and_wait()
        log("%-16s committed prototypes (%.1f min)"
            % (os.path.basename(path), (time.time() - started) / 60))
    log("%-16s named %d, typed %d" % (os.path.basename(path), named, typed))
    return named, typed


def generate(paths, outfile, shipped=(), prototypes=True, log=log):
    """Build `outfile` from every package in `paths`."""
    started = time.time()
    paths = sorted(paths)
    shipped = sorted(shipped)
    build = build_identity(paths, shipped, prototypes)
    claimed = shipped_guids(shipped, log) if shipped else {}
    analysed = []
    try:
        for path in paths:
            bv, rows = candidates(path, log)
            analysed.append((path, rows, bv))
        kept, by_guid, overlap = select([(p, r) for p, r, _ in analysed],
                                        claimed, log)

        if claimed:
            # The same independent check RTTI.md reports, and for the same
            # reason: the overlap is dropped either way, so its agreement rate
            # is a free measurement of whether the rest of the naming is sound.
            agree = sum(1 for g in overlap
                        if {n.lower() for n in claimed[g]}
                        & {n.lower() for n in by_guid[g]})
            log("independent check: of %d GUIDs a shipped library also carries, "
                "%d (%.1f%%) carry the identical name"
                % (len(overlap), agree,
                   100.0 * agree / max(len(overlap), 1)))

        demangler = _Typer() if prototypes else None
        processor = warp.WarpProcessor(
            included_functions=warp.warp_enums.WARPProcessorIncludedFunctions
            .WARPProcessorIncludedFunctionsSelected)
        total = 0
        for path, rows, bv in analysed:
            named, _ = apply(path, bv, rows, kept, demangler, log)
            total += named
            processor.add_binary_view(bv)

        warp_file = processor.start()
        if warp_file is None:
            raise RuntimeError("WARP processor produced nothing")
        with repro.atomic_path(outfile) as temporary:
            with open(temporary, "wb") as handle:
                handle.write(bytes(warp_file.to_data_buffer()))
        repro.write_artifact_manifest(outfile, build)
        log("wrote %s: %d functions, %d bytes (%.1f min)"
            % (outfile, sum(len(c.functions) for c in warp_file.chunks),
               os.path.getsize(outfile), (time.time() - started) / 60))
        return outfile, total
    finally:
        for _, _, view in analysed:
            view.file.close()
