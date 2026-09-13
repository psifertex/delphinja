from pathlib import Path
import unittest

import mapfile


FIXTURE = Path(__file__).parent / "fixtures" / "minimal-delphi.map"


class MapParserTests(unittest.TestCase):
    def test_real_delphi_fixture(self):
        parsed = mapfile.parse_map(FIXTURE.read_bytes())
        self.assertEqual(5, len(parsed.sections))
        self.assertEqual(9, len(parsed.symbols))
        self.assertEqual(12, len(parsed.lines))
        self.assertEqual((2, 0xd0), parsed.entry_point)
        self.assertEqual(0x403c4c,
                         mapfile.preferred_address(parsed, 1, 0x2c4c))
        self.assertEqual("output.MaxArray", parsed.symbols[1].name)
        self.assertEqual("output.pas",
                         parsed.lines[0].source.rsplit("\\", 1)[-1])

    def test_requires_structural_headers(self):
        with self.assertRaises(mapfile.MapFormatError):
            mapfile.parse_map(b"Address Publics by Value\n0001:0 x")
        self.assertFalse(mapfile.looks_like_map(b"not a map"))

    def test_ansi_names_are_lossless(self):
        data = (b"Start Length Name Class\n0001:00401000 20H .text CODE\n"
                b"Address Publics by Value\n0001:00000000 Unit.M\xe9thod\n")
        parsed = mapfile.parse_map(data)
        self.assertEqual("Unit.M\xe9thod", parsed.symbols[0].name)

    def test_offset_must_be_inside_section(self):
        parsed = mapfile.parse_map(
            "Start Length Name Class\n0001:00401000 10H .text CODE\n"
            "Address Publics by Value\n0001:00000010 Unit.Out\n")
        self.assertIsNone(mapfile.preferred_address(parsed, 1, 0x10))

    def test_optional_rva_base_and_object_columns(self):
        parsed = mapfile.parse_map(
            "Start Length Name Class\n0001:00401000 20H .text CODE\n"
            "Address Publics by Value Rva+Base Lib:Object\n"
            "0001:00000008 Unit.Run 00401008 unit.obj\n")
        self.assertEqual(0x401008, parsed.symbols[0].absolute)

    def test_accepts_unsuffixed_section_length(self):
        parsed = mapfile.parse_map(
            "Start Length Name Class\n0001:00401000 20 .text CODE\n"
            "Address Publics by Value\n0001:00000008 Unit.Run\n")
        self.assertEqual(0x20, parsed.sections[0].length)

    def test_duplicate_section_selectors_fail_closed(self):
        with self.assertRaises(mapfile.MapFormatError):
            mapfile.parse_map(
                "Start Length Name Class\n"
                "0001:00401000 20H .text CODE\n"
                "0001:00402000 20H .itext ICODE\n"
                "Address Publics by Value\n0001:00000008 Unit.Run\n")

    def test_rejects_nul_and_oversized_line(self):
        with self.assertRaises(mapfile.MapFormatError):
            mapfile.parse_map(b"Start\x00")
        data = ("Start Length Name Class\n" +
                "x" * (mapfile.MAX_LINE_SIZE + 1) + "\n" +
                "Address Publics by Value\n")
        with self.assertRaises(mapfile.MapFormatError):
            mapfile.parse_map(data)


if __name__ == "__main__":
    unittest.main()
