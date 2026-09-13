import unittest

import binaryninja as bn

from delphinja import mapfile
from delphinja.integration import mapfile as integration


class _Section:
    def __init__(self, start, length):
        self.start, self.length = start, length


class _Segment:
    executable = True


class _Symbol:
    def __init__(self, auto, address=0x5020):
        self.auto = auto
        self.address = address


class _BV:
    sections = {".text": _Section(0x5000, 0x100)}
    platform = None

    def __init__(self, user=False):
        self.user = user

    def is_valid_offset(self, address):
        return 0x5000 <= address < 0x5100

    def get_segment_at(self, address):
        return _Segment() if self.is_valid_offset(address) else None

    def get_symbol_at(self, address):
        return _Symbol(False) if self.user else None

    def get_symbols(self, address, length):
        return [_Symbol(False, address)] if self.user else []

    def get_function_at(self, address):
        return None


class _Info:
    def __init__(self):
        self.functions = []

    def add_function(self, function):
        self.functions.append(function)
        return True


class _MapView:
    start = 0

    def __init__(self, data):
        self.data = data
        self.end = len(data)

    def read(self, offset, length):
        return self.data[offset:offset + length]


class MapIntegrationTests(unittest.TestCase):
    def _parsed(self, extra=""):
        return mapfile.parse_map(
            "Start Length Name Class\n0001:00401000 100H .text CODE\n"
            "Address Publics by Value\n0001:00000020 Unit.Run\n" + extra)

    def test_maps_by_section_for_rebased_view(self):
        info = _Info()
        self.assertEqual((1, 0), integration.contribute(
            self._parsed(), info, _BV()))
        self.assertEqual(0x5020, info.functions[0].address)
        self.assertEqual("Unit.Run", info.functions[0].short_name)
        self.assertIsNone(info.functions[0].raw_name)

    def test_never_overwrites_user_symbol(self):
        info = _Info()
        self.assertEqual((0, 1), integration.contribute(
            self._parsed(), info, _BV(user=True)))
        self.assertEqual([], info.functions)

    def test_ambiguous_aliases_are_not_guessed(self):
        info = _Info()
        parsed = self._parsed("0001:00000020 Unit.Alias\n")
        self.assertEqual((0, 1), integration.contribute(parsed, info, _BV()))

    def test_parser_is_registered_and_recognises_raw_map_view(self):
        self.assertIn(integration.PARSER_NAME,
                      [p.name for p in bn.debuginfo.DebugInfoParser.list])
        data = (b"Start Length Name Class\n"
                b"0001:00401000 20H .text CODE\n"
                b"Address Publics by Value\n0001:0 Unit.Run\n")
        view = bn.BinaryView.new(data)
        try:
            self.assertTrue(integration.is_valid(view))
        finally:
            view.file.close()

    def test_cancellation_precedes_all_contributions(self):
        data = (b"Start Length Name Class\n"
                b"0001:00401000 100H .text CODE\n"
                b"Address Publics by Value\n0001:20 Unit.Run\n")
        info = _Info()
        self.assertFalse(integration.parse_info(
            info, _BV(), _MapView(data), lambda _done, _total: False))
        self.assertEqual([], info.functions)


if __name__ == "__main__":
    unittest.main()
