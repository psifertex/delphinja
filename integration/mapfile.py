"""Binary Ninja DebugInfoParser integration for Delphi text MAP files."""

import binaryninja as bn
from binaryninja import debuginfo

from .. import mapfile


PARSER_NAME = "Delphi MAP"
TAG = "Delphinja"


def _read_all(view):
    if view is None:
        return None
    size = view.end - view.start
    if size < 0 or size > mapfile.MAX_FILE_SIZE:
        return None
    data = view.read(view.start, size)
    return bytes(data) if len(data) == size else None


def is_valid(view):
    try:
        data = _read_all(view)
        return data is not None and mapfile.looks_like_map(data)
    except Exception:
        return False


def _target_address(section, bv, offset, absolute=None):
    if section is None or offset >= section.length:
        return None
    # Prefer a section-name mapping. It remains correct if the view has been
    # rebased, unlike the link-time address printed in the MAP.
    target = bv.sections.get(section.name)
    if target is not None and offset < target.length:
        return target.start + offset
    address = absolute if absolute is not None else section.address + offset
    return address if bv.is_valid_offset(address) else None


def _has_user_name(bv, address):
    # get_symbol_at returns only one of potentially several symbols. Inspect
    # the complete range so a lower-priority user symbol is not hidden by an
    # automatic function or data symbol.
    get_symbols = getattr(bv, "get_symbols", None)
    if get_symbols is not None:
        for symbol in get_symbols(address, 1):
            if symbol.address == address and not symbol.auto:
                return True
    symbol = bv.get_symbol_at(address)
    if symbol is not None and not symbol.auto:
        return True
    function = bv.get_function_at(address)
    return (function is not None and function.symbol is not None and
            not function.symbol.auto)


def contribute(parsed, debug_info, bv):
    """Contribute unambiguous executable publics; return applied/skipped."""
    # Index once: malformed input is allowed up to MAX_RECORDS, so repeatedly
    # searching the section list would otherwise make contribution quadratic.
    sections = {section.selector: section for section in parsed.sections}
    by_address = {}
    for symbol in parsed.symbols:
        address = _target_address(sections.get(symbol.selector), bv,
                                  symbol.offset,
                                  symbol.absolute)
        if address is not None:
            by_address.setdefault(address, set()).add(symbol.name)

    applied = skipped = 0
    for address, names in sorted(by_address.items()):
        segment = bv.get_segment_at(address)
        if (len(names) != 1 or segment is None or not segment.executable or
                _has_user_name(bv, address)):
            skipped += 1
            continue
        name = next(iter(names))
        ok = debug_info.add_function(debuginfo.DebugFunctionInfo(
            # MAP publics are already human-readable Delphi names. Supplying
            # the same value as raw_name can make it win over short_name when
            # Binary Ninja applies the DebugInfo container.
            address=address, short_name=name,
            platform=bv.platform, components=["Delphi MAP"]))
        if ok:
            applied += 1
        else:
            skipped += 1
    return applied, skipped


def parse_info(debug_info, bv, debug_file, progress):
    try:
        data = _read_all(debug_file)
        if data is None:
            return False
        parsed = mapfile.parse_map(data)
        # DebugInfo has no removal API, so observe cancellation before the
        # first contribution and never report cancellation after mutating it.
        if progress is not None and not progress(1, 1):
            return False
        applied, skipped = contribute(parsed, debug_info, bv)
        bn.log_info("MAP contributed %d functions; skipped %d unsafe or "
                    "ambiguous publics; parsed %d source lines"
                    % (applied, skipped, len(parsed.lines)), TAG)
        return True
    except Exception as exc:
        bn.log_error("MAP parse failed: %s" % exc, TAG)
        return False


def register():
    if PARSER_NAME not in [p.name for p in debuginfo.DebugInfoParser.list]:
        debuginfo.DebugInfoParser.register(PARSER_NAME, is_valid, parse_info)
