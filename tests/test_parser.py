import unittest

from tests.support import memory_reader


class ReaderTests(unittest.TestCase):
    def test_integer_reads_stop_at_mapping_boundary(self):
        reader = memory_reader(b"\x78\x56\x34\x12")
        self.assertEqual(reader.u32(0x1000), 0x12345678)
        self.assertIsNone(reader.u32(0x1001))
        self.assertIsNone(reader.u16(0x1003))

    def test_short_string_returns_its_exact_extent(self):
        reader = memory_reader(b"\x07TObject")
        self.assertEqual(reader.shortstr(0x1000), ("TObject", 0x1008))

    def test_truncated_short_string_is_rejected(self):
        reader = memory_reader(b"\x08TObject")
        self.assertEqual(reader.shortstr(0x1000), (None, 0x1000))


if __name__ == "__main__":
    unittest.main()
