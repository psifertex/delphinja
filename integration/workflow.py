"""Delphi metadata recovery as a module workflow.

A workflow can do everything a DebugInfoParser can and two things it cannot:
set comments, and remove functions.  Both matter here.  Delphi stores its RTTI
inside the code section, so linear sweep disassembles the tables into functions;
contributing data variables *before* the sweep stops most of them from ever
existing, and removing the rest afterwards needs an API the debug info path does
not have.  Measured on a Delphi 7 sample: 107 sweep-created functions over
metadata with nothing, 2 with the debug info parser, 0 with this.

The work is split across two activities because the analysis pipeline gives each
half a better vantage point than a single pass would have:

  before core.module.extendedAnalysis   (which is where linear sweep lives)
      scan, define types and data variables, name functions -- early enough to
      pre-empt the sweep, but late enough that entry-point analysis has already
      populated bv.functions

  after core.module.deleteUnusedAutoFunctions   (inside core.module.finishUpdate)
      remove whatever still overlaps metadata, and type Self -- parameter
      variables do not exist until the functions have been analysed, and
      removals made earlier than this point are silently undone
"""

import json
import time

import binaryninja as bn
from binaryninja import Activity, Workflow

from ..rtti import apply as A
from ..rtti import parser as P
from ..rtti import sinks
from . import signatures

ACTIVITY = "analysis.plugins.delphinja"
CLEANUP = "analysis.plugins.delphinjaCleanup"
TAG = A.TAG

# How far into a code section to look for the first VMT before giving up.
# Eligibility runs on every matching load, so it must not become a full scan.
PROBE_LIMIT = 0x40000


def probe(bv):
    """Cheap early-exit search for one plausible VMT.

    A VMT stores its own address at the start of its header, one dword compare
    per candidate, and Delphi emits the System unit's VMTs at the very start of
    the code section -- so a real Delphi binary answers almost immediately and
    anything else costs a bounded scan.

    Every era's header size is tried, not just the 76-byte one: a Delphi 2009
    binary puts its self-pointer 88 bytes back, and probing only for 76 answers
    "not Delphi" for the entire modern range.
    """
    # Free Pascal binaries carry no Delphi VMTs, so the scan below would reject
    # them -- but they still have signature libraries to load. One section
    # lookup settles it, so ask first.
    if signatures.fpc_version(bv) is not None:
        return True
    md = A.DelphiMetadata(bv)
    sizes = P.header_sizes()
    for start, end in md._code_ranges:
        limit = min(end, start + PROBE_LIMIT)
        for addr in P.self_pointers(md.reader, start, limit, sizes):
            if P.parse_vmt(md.reader, md.reader.u32(addr)) is not None:
                return True
    return False


def _state(bv):
    """Per-view scratch. Activities are shared between workflows and must be
    re-entrant, so this cannot be a module-level global."""
    return bv.session_data.setdefault("delphinja", {})


def _eligible(activity, context):
    # Unlike `action`, the eligibility callback receives raw core pointers.
    try:
        bv = bn.workflow.AnalysisContext(context).view
        return bv is not None and probe(bv)
    except Exception:
        return False


def _recover(context):
    bv = context.view
    try:
        # Independent of any Delphi metadata, and cheap, so do it before the
        # scan rather than after: a Free Pascal binary has nothing for the
        # scan to find but still wants its runtime library loaded.
        signatures.register_fpc(bv, TAG)
        t0 = time.time()
        md = A.DelphiMetadata(bv).scan()
        t_scan = time.time() - t0
        # Now that the layout is known, load the signature libraries that can
        # plausibly match this binary -- and only those. This runs before WARP
        # matches, which is the point: registering every library would leave
        # the matcher choosing between versions and declining the ambiguous
        # ones.
        # Only on evidence: with no VMTs this is not a Delphi binary, and its
        # libraries cannot match.
        if md.vmts:
            signatures.register_delphi(TAG)
        t0 = time.time()
        sink = sinks.AutoSink(bv, md)
        stats = A.Applier(md, {"undefine": False}, sink=sink).run()
        bn.log_info("timing: scan %.2fs apply %.2fs" % (t_scan, time.time() - t0), TAG)
        _state(bv).update(md=md, pending_self=list(sink.pending_self),
                          cc=sink.cc)
        bn.log_info("recovered %d names, %d data variables, %d comments, %d types"
                    % (stats["functions_named"], stats["data_vars"],
                       stats["comments"], stats["structs"] + stats["enums"]),
                    TAG)
    except Exception as exc:
        # Activity exceptions are swallowed by the core; say something first.
        bn.log_error("recovery failed: %s" % exc, TAG)


def _cleanup(context):
    bv = context.view
    try:
        state = _state(bv)
        md = state.get("md")
        if md is None:
            return
        t0 = time.time()
        spans = [(s, e) for s, e, _ in md.spans()]
        removed = A.undefine_functions(bv, spans, lambda m: bn.log_info(m, TAG))
        t_undef = time.time() - t0
        t0 = time.time()
        typed = 0
        conventions = 0
        cc = state.get("cc")
        for addr, self_type, register_cc in state.get("pending_self", ()):
            func = bv.get_function_at(addr)
            if func is None:
                continue
            method_cc = cc if register_cc else None
            try:
                typed += sinks.apply_method(func, self_type, method_cc)
            except Exception:
                continue
            if method_cc is not None:
                conventions += 1
        state.clear()
        bn.log_info("timing: undefine %.2fs self %.2fs" % (t_undef, time.time() - t0), TAG)
        bn.log_info("removed %d functions over metadata, set the register "
                    "convention on %d methods, typed %d Self parameters"
                    % (len(removed), conventions, typed), TAG)
    except Exception as exc:
        bn.log_error("cleanup failed: %s" % exc, TAG)


def register():
    """Clone the module workflow and splice both activities into it.

    Cloning the already-registered core workflow composes with the other
    analysis plugins rather than replacing them, and the clone lives only for
    this session -- workflows are rebuilt from scratch on each start.
    """
    workflow = Workflow("core.module.metaAnalysis").clone()
    if workflow is None:
        return

    workflow.register_activity(Activity(
        configuration=json.dumps({
            "name": ACTIVITY,
            "title": "Delphi RTTI",
            "role": "action",
            "description": "Recover Delphi/VCL class metadata before linear sweep.",
            "eligibility": {
                "runOnce": True,
                "auto": {},
                "predicates": [
                    {"type": "platform", "value": ["windows-x86"],
                     "operator": "in"},
                    {"type": "setting", "identifier": ACTIVITY, "value": True},
                ],
            },
            # Without this analysis does not always re-trigger after the
            # activity changes the view.
            "dependencies": {"downstream": ["core.module.update"]},
        }),
        action=_recover,
        eligibility=_eligible))

    workflow.register_activity(Activity(
        configuration=json.dumps({
            "name": CLEANUP,
            "title": "Delphi RTTI Cleanup",
            "role": "action",
            "description": "Remove sweep-created functions overlapping Delphi metadata.",
            "eligibility": {
                "runOnce": True,
                "auto": {},
                # Same gate as the recovery activity. Without it this runs a
                # Python callback on every binary opened, only to find there is
                # no recovery state and return.
                "predicates": [
                    {"type": "platform", "value": ["windows-x86"],
                     "operator": "in"},
                    {"type": "setting", "identifier": CLEANUP, "value": True},
                ],
            },
        }),
        action=_cleanup))

    workflow.insert("core.module.extendedAnalysis", [ACTIVITY])
    workflow.insert_after("core.module.deleteUnusedAutoFunctions", [CLEANUP])
    workflow.register()
