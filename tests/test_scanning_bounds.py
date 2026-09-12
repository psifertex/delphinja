import struct
import unittest
from unittest import mock

from tests.support import memory_reader


class _Section(object):
    def __init__(self, start, end, semantics):
        self.start = start
        self.end = end
        self.semantics = semantics


class _View(object):
    def __init__(self, start, size, semantics):
        self.start = start
        self.end = start + size
        self.address_size = 4
        self.sections = {"text": _Section(self.start, self.end, semantics)}
        self.reads = []

    def read(self, addr, length):
        self.reads.append((addr, length))
        if addr < self.start or addr + length > self.end:
            return b""
        return bytes((addr + i) & 0xff for i in range(length))

    def is_valid_offset(self, addr):
        return self.start <= addr < self.end


class MetadataReadTests(unittest.TestCase):
    def test_code_sections_are_cached_lazily_in_bounded_blocks(self):
        import binaryninja as bn
        from delphinja.rtti import apply

        chunk = apply.DelphiMetadata.READ_CHUNK
        view = _View(0x1000, chunk * 12 + 31,
                     bn.SectionSemantics.ReadOnlyCodeSectionSemantics)
        with mock.patch.object(apply.P, "detect_layout",
                               return_value=(None, 0)):
            metadata = apply.DelphiMetadata(view)

        self.assertEqual(view.reads, [])
        for index in range(12):
            addr = view.start + index * chunk
            self.assertEqual(metadata.reader.bytes(addr, 1),
                             bytes([addr & 0xff]))

        self.assertLessEqual(len(metadata._cache),
                             metadata.READ_CACHE_CHUNKS)
        self.assertTrue(view.reads)
        self.assertLessEqual(max(length for _, length in view.reads), chunk)

    def test_cached_read_reassembles_a_request_across_block_boundary(self):
        import binaryninja as bn
        from delphinja.rtti import apply

        chunk = apply.DelphiMetadata.READ_CHUNK
        view = _View(0x2000, chunk * 2,
                     bn.SectionSemantics.ReadOnlyCodeSectionSemantics)
        with mock.patch.object(apply.P, "detect_layout",
                               return_value=(None, 0)):
            metadata = apply.DelphiMetadata(view)

        addr = view.start + chunk - 3
        expected = bytes((addr + i) & 0xff for i in range(9))
        self.assertEqual(metadata.reader.bytes(addr, 9), expected)
        self.assertLessEqual(max(length for _, length in view.reads), chunk)


class StreamingScanTests(unittest.TestCase):
    def _tracking_reader(self, data, base=0x4000):
        from delphinja.rtti.parser import Reader

        calls = []
        end = base + len(data)

        def read(addr, length):
            calls.append((addr, length))
            if addr < base or addr + length > end:
                return b""
            offset = addr - base
            return data[offset:offset + length]

        reader = Reader(read, lambda addr: base <= addr < end)
        return reader, calls

    def test_headerless_candidate_crosses_scanner_block_boundary(self):
        from delphinja.rtti import parser

        base = 0x4000
        literal_addr = base + parser._CHUNK - 4
        text = b"BoundaryValue"
        data = bytearray(parser._CHUNK + len(text) + 8)
        offset = literal_addr - base
        data[offset:offset + len(text) + 1] = text + b"\0"
        reader, calls = self._tracking_reader(bytes(data), base)

        found = list(parser.headerless_candidates(reader, base,
                                                   base + len(data)))

        self.assertEqual([(item.addr, item.raw) for item in found],
                         [(literal_addr, text)])
        self.assertLessEqual(max(length for _, length in calls), parser._CHUNK)

    def test_wide_candidate_crosses_scanner_block_boundary(self):
        from delphinja.rtti import parser

        base = 0x4000
        literal_addr = base + parser._CHUNK - 4
        text = "BoundaryValue"
        raw = text.encode("utf-16-le")
        data = bytearray(parser._CHUNK + len(raw) + 8)
        offset = literal_addr - base
        data[offset:offset + len(raw) + 2] = raw + b"\0\0"
        reader, calls = self._tracking_reader(bytes(data), base)

        found = list(parser.headerless_candidates(
            reader, base, base + len(data), wide=True))

        self.assertEqual([(item.addr, item.text) for item in found],
                         [(literal_addr, text)])
        self.assertLessEqual(max(length for _, length in calls), parser._CHUNK)

    def test_overlong_run_is_not_recovered_from_its_tail(self):
        from delphinja.rtti import parser

        base = 0x4000
        data = b"A" * (parser.MAX_STRING_LENGTH + 1) + b"\0"
        reader, _calls = self._tracking_reader(data, base)

        found = list(parser.headerless_candidates(
            reader, base, base + len(data)))

        self.assertEqual(found, [])

    def test_pointer_target_crosses_scanner_block_boundary(self):
        from delphinja.rtti import parser

        base = 0x8000
        target = 0x12345678
        offset = parser._CHUNK - 2
        data = bytearray(parser._CHUNK + 8)
        data[offset:offset + 4] = struct.pack("<I", target)
        reader, calls = self._tracking_reader(bytes(data), base)

        found = parser.pointer_targets(
            reader, [(base, base + len(data))], [target])

        self.assertEqual(found, {target})
        self.assertLessEqual(max(length for _, length in calls), parser._CHUNK)


if __name__ == "__main__":
    unittest.main()
