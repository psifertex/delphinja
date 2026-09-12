import struct
import unittest

from tests.support import memory_reader


BASE = 0x2000


def _shortstr(text):
    raw = text.encode("latin-1")
    return bytes([len(raw)]) + raw


def _classic_method(name, code=BASE):
    body = struct.pack("<I", code) + _shortstr(name)
    return struct.pack("<H", len(body) + 2) + body


def _vmt(slot, address=BASE):
    from delphinja.rtti.parser import Vmt

    vmt = Vmt(0x4000)
    vmt.slots[slot] = address
    return vmt


class MethodTableTests(unittest.TestCase):
    def test_valid_classic_table_is_committed(self):
        from delphinja.rtti.parser import _parse_method_table

        data = struct.pack("<H", 2)
        data += _classic_method("Create")
        data += _classic_method("Destroy")
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtMethodTable")

        _parse_method_table(reader, vmt)

        self.assertEqual([m["name"] for m in vmt.methods],
                         ["Create", "Destroy"])
        self.assertEqual(vmt.regions,
                         [(BASE, BASE + len(data), "MethodTable")])

    def test_complete_tailed_method_is_committed(self):
        from delphinja.rtti.parser import _parse_method_table

        body = struct.pack("<I", BASE) + _shortstr("Run")
        body += struct.pack("<BBIhB", 1, 0, 0, 0, 0) + b"\x02\x00"
        entry = struct.pack("<H", len(body) + 2) + body
        data = struct.pack("<H", 1) + entry
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtMethodTable")

        _parse_method_table(reader, vmt)

        self.assertEqual([m["name"] for m in vmt.methods], ["Run"])
        self.assertTrue(vmt.methods[0]["complete"])
        self.assertEqual(vmt.regions,
                         [(BASE, BASE + len(data), "MethodTable")])

    def test_untrusted_entry_length_claims_nothing(self):
        from delphinja.rtti.parser import _parse_method_table

        # This is the original ten-byte reproducer: the head is plausible,
        # but Len points almost 64 KiB past the bytes that are actually there.
        data = struct.pack("<HHI", 1, 0xFFFF, BASE) + _shortstr("A")
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtMethodTable")

        _parse_method_table(reader, vmt)

        self.assertEqual(vmt.methods, [])
        self.assertEqual(vmt.regions, [])

    def test_late_bad_entry_rolls_back_earlier_methods(self):
        from delphinja.rtti.parser import _parse_method_table

        data = struct.pack("<H", 2) + _classic_method("Good")
        data += struct.pack("<HI", 0xFFFF, BASE) + _shortstr("Bad")
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtMethodTable")

        _parse_method_table(reader, vmt)

        self.assertEqual(vmt.methods, [])
        self.assertEqual(vmt.regions, [])

    def test_truncated_attribute_blob_cannot_satisfy_entry_length(self):
        from delphinja.rtti.parser import _parse_method_table

        entry_size = 0x40
        head = struct.pack("<HI", entry_size, BASE) + _shortstr("A")
        tail = struct.pack("<BBIhB", 1, 0, 0, 0, 0)
        attr_length = entry_size - len(head) - len(tail)
        data = struct.pack("<H", 1) + head + tail
        data += struct.pack("<H", attr_length)
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtMethodTable")

        _parse_method_table(reader, vmt)

        self.assertEqual(vmt.methods, [])
        self.assertEqual(vmt.regions, [])

    def test_method_code_must_point_to_code(self):
        from delphinja.rtti.parser import _parse_method_table

        data = struct.pack("<H", 1) + _classic_method("A", code=0x9000)
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtMethodTable")

        _parse_method_table(reader, vmt)

        self.assertEqual(vmt.methods, [])
        self.assertEqual(vmt.regions, [])


class AdjacentTableTests(unittest.TestCase):
    def test_valid_field_table_is_committed(self):
        from delphinja.rtti.parser import _parse_field_table

        data = struct.pack("<HI", 1, 0)
        data += struct.pack("<IH", 12, 0) + _shortstr("Owner")
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtFieldTable")

        _parse_field_table(reader, vmt)

        self.assertEqual([field["name"] for field in vmt.fields], ["Owner"])
        self.assertEqual(vmt.regions,
                         [(BASE, BASE + len(data), "FieldTable")])

    def test_truncated_field_header_claims_nothing(self):
        from delphinja.rtti.parser import _parse_field_table

        reader = memory_reader(struct.pack("<H", 0), base=BASE)
        vmt = _vmt("vmtFieldTable")

        _parse_field_table(reader, vmt)

        self.assertEqual(vmt.fields, [])
        self.assertEqual(vmt.regions, [])

    def test_late_bad_field_rolls_back_earlier_fields(self):
        from delphinja.rtti.parser import _parse_field_table

        data = struct.pack("<HI", 2, 0)
        data += struct.pack("<IH", 4, 0) + _shortstr("Good")
        data += struct.pack("<IH", 8, 0) + b"\x04B"
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtFieldTable")

        _parse_field_table(reader, vmt)

        self.assertEqual(vmt.fields, [])
        self.assertEqual(vmt.regions, [])

    def test_truncated_field_class_table_is_not_claimed(self):
        from delphinja.rtti.parser import _parse_field_table

        class_table = BASE + 6
        data = struct.pack("<HIHI", 0, class_table, 2, 0x4000)
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtFieldTable")

        _parse_field_table(reader, vmt)

        self.assertEqual(vmt.field_classes, [])
        self.assertEqual(vmt.regions, [(BASE, class_table, "FieldTable")])

    def test_truncated_interface_table_is_transactional(self):
        from delphinja.rtti.parser import _parse_intf_table

        entry = bytes(16) + struct.pack("<IiI", 0, 0, 0)
        data = struct.pack("<i", 2) + entry + bytes(16)
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtIntfTable")

        _parse_intf_table(reader, vmt)

        self.assertEqual(vmt.interfaces, [])
        self.assertEqual(vmt.regions, [])

    def test_valid_interface_table_is_committed(self):
        from delphinja.rtti.parser import _parse_intf_table

        entry = bytes(range(16)) + struct.pack("<IiI", 0, 12, 0)
        data = struct.pack("<i", 1) + entry
        reader = memory_reader(data, base=BASE)
        vmt = _vmt("vmtIntfTable")

        _parse_intf_table(reader, vmt)

        self.assertEqual(len(vmt.interfaces), 1)
        self.assertEqual(vmt.interfaces[0]["offset"], 12)
        self.assertEqual(vmt.regions,
                         [(BASE, BASE + len(data), "IntfTable")])


if __name__ == "__main__":
    unittest.main()
