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

import bisect
import json

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
RECOVERY_PLATFORMS = ["windows-x86", "windows-x86_64"]

# Callback discovery is a late convenience pass, not another whole-program
# analysis engine.  Code references let it visit only calls to typed callback
# consumers, and these caps keep even adversarial binaries from making the
# workflow activity unbounded.
CALLBACK_FUNCTION_LIMIT = 100000
CALLBACK_REFS_PER_FUNCTION = 4096
CALLBACK_REFERENCE_LIMIT = 100000
CALLBACK_TARGET_LIMIT = 4096
CALLBACK_TYPE_DEPTH = 16

_CONSTANT_VALUES = {
    bn.RegisterValueType.ConstantValue,
    bn.RegisterValueType.ConstantPointerValue,
}


def probe(bv):
    """Cheap early-exit search for one plausible VMT.

    From Delphi 3 a VMT stores its own address at the start of its header, one
    dword compare per candidate, and Delphi emits the System unit's VMTs at the
    very start of the code section -- so a real Delphi binary answers almost
    immediately and anything else costs a bounded scan.

    `find_vmt` tries every era, which is what this has to do in both
    directions.  A Delphi 2009 binary puts its self-pointer 88 bytes back, so
    probing only for 76 answers "not Delphi" for the entire modern range; and a
    Delphi 2 binary has no self-pointer at all, so probing only for one answers
    "not Delphi" for the oldest era and skips *both* activities -- including
    the string constants the parser can read out of it with no VMT involved.
    """
    # Free Pascal binaries carry no Delphi VMTs, so the scan below would reject
    # them -- but they still have signature libraries to load. One section
    # lookup settles it, so ask first.
    if signatures.fpc_version(bv) is not None:
        return True
    # The shipped Win64 support is an FPC WARP library, not a claim that this
    # 32-bit Delphi RTTI decoder understands Win64 Delphi layouts.  Once the
    # positive FPC test fails, do not inspect an eight-byte view as Delphi.
    if bv.arch is None or bv.arch.address_size != 4:
        return False
    md = A.DelphiMetadata(bv)
    return P.find_vmt(md.reader, md._code_ranges, PROBE_LIMIT) is not None


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


def _known_constant(value):
    """Return a RegisterValue's single known constant, if it has one."""
    try:
        if value.type in _CONSTANT_VALUES:
            return value.value
    except (AttributeError, ValueError):
        pass
    return None


def _resolve_named_type(bv, ty):
    """Peel a bounded chain of named typedefs, rejecting cycles."""
    seen = set()
    for _depth in range(CALLBACK_TYPE_DEPTH):
        try:
            if ty.type_class != bn.TypeClass.NamedTypeReferenceClass:
                return ty
            type_id = ty.type_id
        except (AttributeError, ValueError):
            return None
        if type_id in seen:
            return None
        seen.add(type_id)
        try:
            ty = bv.get_type_by_id(type_id)
        except (AttributeError, ValueError):
            return None
        if ty is None:
            return None
    return None


def _callback_parameter_indexes(bv, function_type):
    """Indexes of plain function-pointer parameters in a function type.

    Delphi ``of object`` method values are deliberately outside this shape:
    they are a code pointer plus a Self pointer, not a plain pointer to a
    function, and need different data-flow handling.
    """
    result = []
    try:
        parameters = function_type.parameters
    except (AttributeError, ValueError):
        return result
    for index, parameter in enumerate(parameters):
        try:
            ty = _resolve_named_type(bv, parameter.type)
            if ty is None:
                continue
            if ty.type_class != bn.TypeClass.PointerTypeClass:
                continue
            target = _resolve_named_type(bv, ty.target)
            if (target is not None and
                    target.type_class == bn.TypeClass.FunctionTypeClass):
                result.append(index)
        except (AttributeError, ValueError):
            continue
    return result


def _merged_spans(spans):
    """Sorted, non-overlapping metadata ranges for fast target rejection."""
    merged = []
    for start, end in sorted(spans):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _in_spans(addr, spans, starts):
    index = bisect.bisect_right(starts, addr) - 1
    return index >= 0 and addr < spans[index][1]


def _analysis_aborted(bv):
    try:
        aborted = bv.analysis_is_aborted
        return (aborted() if callable(aborted) else aborted) is True
    except Exception:
        return False


def _inside_user_function(bv, addr):
    """Whether a containing function carries explicit analyst state."""
    try:
        containing = bv.get_functions_containing(addr)
    except Exception:
        return True
    for function in containing:
        try:
            annotations = function.has_user_annotations
            annotations = annotations() if callable(annotations) else annotations
            if annotations:
                return True
        except Exception:
            return True
    return False


def discover_callbacks(bv, metadata_spans=()):
    """Create auto functions for constant, executable callback arguments.

    This consumes the function-pointer types already attached to callees by
    WARP, imports, or the analyst.  It intentionally handles direct calls
    only: a code reference proves which function type belongs to the call,
    while guessing an indirect destination would undermine the conservative
    target checks below.
    """
    spans = _merged_spans(metadata_spans)
    starts = [start for start, _end in spans]
    candidates = set()
    references = 0

    for function_index, callee in enumerate(bv.functions):
        if function_index >= CALLBACK_FUNCTION_LIMIT:
            break
        if _analysis_aborted(bv):
            return 0
        try:
            function_type = callee.type
        except (AttributeError, ValueError):
            continue
        indexes = _callback_parameter_indexes(bv, function_type)
        if not indexes:
            continue
        remaining = CALLBACK_REFERENCE_LIMIT - references
        if remaining <= 0:
            break
        maximum = min(CALLBACK_REFS_PER_FUNCTION, remaining)
        for ref in bv.get_code_refs(callee.start, max_items=maximum):
            references += 1
            if _analysis_aborted(bv):
                return 0
            try:
                if (ref.function is None or
                        not isinstance(ref.llil, bn.Call) or
                        callee.start not in bv.get_callees(
                            ref.address, ref.function, ref.arch)):
                    continue
            except (AttributeError, ValueError):
                continue
            for index in indexes:
                try:
                    value = ref.function.get_parameter_at(
                        ref.address, function_type, index, ref.arch)
                except (AttributeError, ValueError):
                    continue
                target = _known_constant(value)
                if (target is None or target in candidates or
                        not bv.is_valid_offset(target) or
                        not bv.is_offset_executable(target) or
                        _in_spans(target, spans, starts) or
                        bv.get_function_at(target) is not None or
                        _inside_user_function(bv, target)):
                    continue
                candidates.add(target)
                if len(candidates) >= CALLBACK_TARGET_LIMIT:
                    break
            if len(candidates) >= CALLBACK_TARGET_LIMIT:
                break
        if (references >= CALLBACK_REFERENCE_LIMIT or
                len(candidates) >= CALLBACK_TARGET_LIMIT):
            break

    if _analysis_aborted(bv):
        return 0

    # add_function creates analysis-owned state.  Do not use
    # auto_discovered=True here: deleteUnusedAutoFunctions can discard such
    # functions, and the callback pass itself runs immediately after it.
    created = []
    for target in sorted(candidates):
        if _analysis_aborted(bv):
            for function in reversed(created):
                bv.remove_function(function)
            return 0
        if (bv.get_function_at(target) is not None or
                _inside_user_function(bv, target)):
            continue
        function = bv.add_function(target)
        if function is not None:
            created.append(function)
    if _analysis_aborted(bv):
        for function in reversed(created):
            bv.remove_function(function)
        return 0
    return len(created)


def _recover(context):
    bv = context.view
    try:
        # Independent of any Delphi metadata, and cheap, so do it before the
        # scan rather than after: a Free Pascal binary has nothing for the
        # scan to find but still wants its runtime library loaded.
        fpc_version = signatures.fpc_version(bv)
        if fpc_version is not None:
            signatures.register_fpc(bv, TAG, version=fpc_version)
            return
        if bv.arch is None or bv.arch.address_size != 4:
            return
        md = A.DelphiMetadata(bv).scan()
        # Now that the layout is known, load the signature libraries that can
        # plausibly match this binary -- and only those. This runs before WARP
        # matches, which is the point: registering every library would leave
        # the matcher choosing between versions and declining the ambiguous
        # ones.
        # Only on evidence: with no VMTs this is not a Delphi binary, and its
        # libraries cannot match.
        if md.vmts:
            signatures.register_delphi(md.layout, TAG)
        sink = sinks.AutoSink(bv, md)
        stats = A.Applier(md, {"undefine": False}, sink=sink).run()
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
        spans = [(s, e) for s, e, _ in md.spans()]
        removed = A.undefine_functions(bv, spans, lambda m: bn.log_debug(m, TAG))
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
        callbacks = discover_callbacks(bv, spans)
        state.clear()
        bn.log_info("removed %d functions over metadata, set the register "
                    "convention on %d methods, typed %d Self parameters, "
                    "created %d callback functions"
                    % (len(removed), conventions, typed, callbacks), TAG)
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
                    {"type": "platform", "value": RECOVERY_PLATFORMS,
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
            # This activity sets calling conventions and creates the Self
            # variables, so it changes the view no less than recovery does and
            # needs the same downstream update.  Without it the writes land but
            # nothing re-renders: the types are correct in the database and
            # appear the moment anything else forces an analysis update.
            "dependencies": {"downstream": ["core.module.update"]},
        }),
        action=_cleanup))

    workflow.insert("core.module.extendedAnalysis", [ACTIVITY])
    workflow.insert_after("core.module.deleteUnusedAutoFunctions", [CLEANUP])
    workflow.register()
