"""Bounded, Binary-Ninja-independent parser for Delphi text MAP files."""

from dataclasses import dataclass
import re


MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_LINE_SIZE = 64 * 1024
MAX_RECORDS = 1_000_000
MAX_NAME_SIZE = 4096


class MapFormatError(ValueError):
    pass


@dataclass(frozen=True)
class MapSection:
    selector: int
    address: int
    length: int
    name: str
    kind: str


@dataclass(frozen=True)
class MapSymbol:
    selector: int
    offset: int
    name: str
    absolute: object = None


@dataclass(frozen=True)
class MapLine:
    selector: int
    offset: int
    line: int
    module: str
    source: str


@dataclass(frozen=True)
class DelphiMap:
    sections: tuple
    symbols: tuple
    lines: tuple
    entry_point: object = None


_SECTION = re.compile(
    r"^\s*([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,16})\s+"
    r"([0-9a-fA-F]{1,16})(?:[Hh])?\s+(\S+)\s+(\S+)\s*$")
_SYMBOL = re.compile(
    r"^\s*([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,16})\s+(\S+)"
    r"(?:\s+([0-9a-fA-F]{8,16})(?:\s+\S.*)?)?\s*$")
_LINE_PAIR = re.compile(
    r"(\d+)\s+([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,16})(?=\s|$)")
_ENTRY = re.compile(
    r"^\s*Program entry point at\s+([0-9a-fA-F]{1,8}):"
    r"([0-9a-fA-F]{1,16})\s*$", re.I)


def _text(data):
    if isinstance(data, str):
        raw = data.encode("utf-8", "surrogatepass")
        text = data
    else:
        raw = bytes(data)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            # Delphi historically emitted MAP files in the active ANSI code
            # page. Latin-1 is lossless and symbol delimiters remain ASCII.
            text = raw.decode("latin-1")
    if len(raw) > MAX_FILE_SIZE:
        raise MapFormatError("MAP file exceeds %d-byte limit" % MAX_FILE_SIZE)
    if "\x00" in text:
        raise MapFormatError("MAP file contains NUL bytes")
    return text


def looks_like_map(data):
    """Return whether *data* has the two structural Delphi MAP headers."""
    try:
        text = _text(data)
    except (MapFormatError, TypeError, ValueError):
        return False
    return (re.search(r"(?im)^\s*Start\s+Length\s+Name\s+Class\s*$", text)
            is not None and
            re.search(r"(?im)^\s*Address\s+Publics by Value(?:\s+.*)?$", text)
            is not None)


def parse_map(data):
    """Parse the sections, value-sorted publics and source line records.

    Unknown sections and malformed individual records are ignored. Structural
    headers are mandatory, and all resource limits are checked before records
    are retained.
    """
    text = _text(data)
    sections, symbols, lines = [], [], []
    mode = None
    source = module = None
    saw_sections = saw_values = False
    entry = None

    for raw_line in text.splitlines():
        if len(raw_line) > MAX_LINE_SIZE:
            raise MapFormatError("MAP line exceeds %d-byte limit" % MAX_LINE_SIZE)
        stripped = raw_line.strip()
        lower = stripped.lower()
        if re.fullmatch(r"start\s+length\s+name\s+class", lower):
            mode, saw_sections = "sections", True
            continue
        if re.match(r"address\s+publics by value(?:\s|$)", lower):
            mode, saw_values = "symbols", True
            continue
        if re.match(r"address\s+publics by name(?:\s|$)", lower):
            mode = None                 # intentionally avoid duplicate publics
            continue
        if lower.startswith("address "):
            # Other linker tables can contain the same segment:offset/name
            # shape; do not accidentally promote their rows to publics.
            mode = None
            continue
        if lower.startswith("detailed map of segments"):
            mode = None
            continue
        if lower in ("bound resource files", "exports"):
            mode = None
            continue
        if lower.startswith("line numbers for "):
            tail = stripped[len("Line numbers for "):]
            marker = tail.lower().rfind(" segment ")
            label = tail[:marker] if marker >= 0 else tail
            left = label.find("(")
            right = label.rfind(")")
            if 0 <= left < right:
                module = label[:left].strip()
                source = label[left + 1:right]
                if (len(module) > MAX_NAME_SIZE or
                        len(source) > MAX_NAME_SIZE):
                    raise MapFormatError("MAP source name exceeds limit")
                mode = "lines"
            else:
                mode = None
            continue

        match = _ENTRY.match(raw_line)
        if match:
            entry = (int(match.group(1), 16), int(match.group(2), 16))
            mode = None
            continue

        if mode == "sections":
            match = _SECTION.match(raw_line)
            if match:
                name, kind = match.group(4), match.group(5)
                if len(name) > MAX_NAME_SIZE or len(kind) > MAX_NAME_SIZE:
                    raise MapFormatError("MAP section name exceeds limit")
                sections.append(MapSection(
                    int(match.group(1), 16), int(match.group(2), 16),
                    int(match.group(3), 16), name, kind))
        elif mode == "symbols":
            match = _SYMBOL.match(raw_line)
            if match:
                name = match.group(3)
                if len(name) > MAX_NAME_SIZE:
                    raise MapFormatError("MAP symbol name exceeds limit")
                absolute = (int(match.group(4), 16)
                            if match.group(4) is not None else None)
                symbols.append(MapSymbol(int(match.group(1), 16),
                                         int(match.group(2), 16), name,
                                         absolute))
        elif mode == "lines" and module is not None:
            for match in _LINE_PAIR.finditer(raw_line):
                lines.append(MapLine(int(match.group(2), 16),
                                     int(match.group(3), 16),
                                     int(match.group(1)), module, source))

        if len(sections) + len(symbols) + len(lines) > MAX_RECORDS:
            raise MapFormatError("MAP record count exceeds limit")

    if not saw_sections or not saw_values:
        raise MapFormatError("not a detailed Delphi MAP file")
    if not sections:
        raise MapFormatError("MAP file has no valid sections")
    selectors = [section.selector for section in sections]
    if len(selectors) != len(set(selectors)):
        raise MapFormatError("MAP file has duplicate section selectors")
    return DelphiMap(tuple(sections), tuple(symbols), tuple(lines), entry)


def preferred_address(map_file, selector, offset):
    """Resolve a segment:offset pair using the MAP section table."""
    section = next((s for s in map_file.sections if s.selector == selector), None)
    if section is None or offset >= section.length:
        return None
    return section.address + offset
