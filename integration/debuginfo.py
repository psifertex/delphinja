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

    A VMT stores its own address one header back, which is a single dword
    compare per candidate, and Delphi emits the System unit's VMTs at the very
    start of the code section -- so a real Delphi binary answers almost
    immediately.
    """
    if signatures.fpc_version(bv) is not None:
        return True                 # Free Pascal: no VMTs, but libraries to load
    md = A.DelphiMetadata(bv)
    # Every era's header size, not just the 76-byte one: a Delphi 2009 binary
    # puts its self-pointer 88 bytes back, and probing only for 76 answers
    # "not Delphi" for the whole modern range.
    sizes = P.header_sizes()
    for start, end in md._code_ranges:
        limit = min(end, start + PROBE_LIMIT)
        for addr in P.self_pointers(md.reader, start, limit, sizes):
            if P.parse_vmt(md.reader, md.reader.u32(addr)) is not None:
                return True
    return False


def is_valid(bv):
    if bv is None or bv.arch is None or bv.arch.address_size != 4:
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
        md = A.DelphiMetadata(bv)
        cancelled = [False]

        def report(done, total):
            if progress is not None and not progress(done, max(total, 1)):
                cancelled[0] = True
                return False
            return True

        t0 = time.time()
        md.scan(None, report)
        t_scan = time.time() - t0
        if cancelled[0]:
            return False
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
    except Exception as exc:
        bn.log_error("parse failed: %s" % exc, TAG)
        return False


def register():
    if PARSER_NAME not in [p.name for p in debuginfo.DebugInfoParser.list]:
        debuginfo.DebugInfoParser.register(PARSER_NAME, is_valid, parse_info)
