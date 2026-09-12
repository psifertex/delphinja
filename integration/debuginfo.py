"""Delphi metadata as a DebugInfo parser.

A DebugInfo parser runs during the Discovery phase, before linear sweep has
finished inventing functions over the RTTI tables, so contributing the
metadata as data variables at that point stops most of the bogus functions
from ever existing.

What it cannot do is remove functions or set comments -- neither has an entry
point in the debug info API at any layer -- so the plugin keeps commands for
both, which are also how a database analysed without the parser is repaired.
"""

import time

import binaryninja as bn
from binaryninja import debuginfo

from ..rtti import apply as A
from ..rtti import parser as P
from ..rtti import sinks
from . import signatures

PARSER_NAME = "Delphi RTTI"
TAG = A.TAG

# How far into a code section to look for the first VMT before giving up.
# is_valid runs on every file load, so it must not turn into a full scan.
PROBE_LIMIT = 0x40000


def _probe(bv):
    """Cheap early-exit search for one plausible VMT.

    From Delphi 3 a VMT stores its own address one header back, which is a
    single dword compare per candidate, and Delphi emits the System unit's VMTs
    at the very start of the code section -- so a real Delphi binary answers
    almost immediately.  `find_vmt` tries every era's anchor, including the
    Delphi 2 header that has no self-pointer to compare against at all.
    """
    if signatures.fpc_version(bv) is not None:
        return True                 # Free Pascal: no VMTs, but libraries to load
    # Win64 is supported here only for the shipped Free Pascal signatures.
    # Absence of that evidence must not turn into an unvalidated Delphi x64
    # RTTI scan.
    if bv.arch is None or bv.arch.address_size != 4:
        return False
    md = A.DelphiMetadata(bv)
    return P.find_vmt(md.reader, md._code_ranges, PROBE_LIMIT) is not None


def is_valid(bv):
    if bv is None or bv.arch is None or bv.arch.address_size not in (4, 8):
        return False
    if bv.view_type != "PE":
        return False
    try:
        return _probe(bv)
    except Exception:
        return False


def parse_info(debug_info, bv, debug_file, progress):
    """Contribute every recovered type, data variable and function name."""
    try:
        # FPC carries no Delphi RTTI for this decoder to contribute.  The
        # parser participates so it can register the matching WARP library;
        # on Win64 in particular, stop there rather than implying Delphi x64
        # metadata support.
        fpc_version = signatures.fpc_version(bv)
        if fpc_version is not None:
            signatures.register_fpc(bv, TAG, version=fpc_version)
            return True
        if bv.arch is None or bv.arch.address_size != 4:
            return False
        def report(done, total):
            if progress is not None and not progress(done, max(total, 1)):
                return False
            return True

        t0 = time.time()
        md = A.DelphiMetadata(bv, report)
        md.scan(None, report, scan_dfm=A.setting("dfm"))
        t_scan = time.time() - t0
        # Only on evidence -- see the note in workflow.py.
        if md.vmts:
            signatures.register_delphi(md.layout, TAG)
        signatures.register_fpc(bv, TAG)

        t0 = time.time()
        sink = sinks.DebugInfoSink(debug_info, bv, md)
        stats = A.Applier(md, {
            "undefine": False,       # impossible here, and unnecessary:
                                     # the data variables pre-empt the sweep
            "comments": False,       # no entry point in the debug info API
        }, sink=sink).run()
        # Timings are logged so a slow load can be attributed to this parser or
        # ruled out from the log alone, without instrumenting a build.
        bn.log_info("timing: scan %.2fs apply %.2fs" % (t_scan, time.time() - t0),
                    TAG)
        bn.log_info("contributed %d functions, %d data variables, %d types"
                    % (stats["functions_named"], stats["data_vars"],
                       stats["structs"] + stats["enums"]), TAG)
        return True
    except P.ScanCancelled:
        return False
    except Exception as exc:
        bn.log_error("parse failed: %s" % exc, TAG)
        return False


def register():
    if PARSER_NAME not in [p.name for p in debuginfo.DebugInfoParser.list]:
        debuginfo.DebugInfoParser.register(PARSER_NAME, is_valid, parse_info)
