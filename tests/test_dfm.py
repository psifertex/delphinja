import unittest

from tests.support import memory_reader


def _short(text):
    raw = text.encode("latin-1")
    return bytes([len(raw)]) + raw


class _Vmt(object):
    def __init__(self, name, methods=(), methods_ex=()):
        self.name = name
        self.methods = list(methods)
        self.methods_ex = list(methods_ex)


class _Metadata(object):
    def __init__(self, vmts):
        self.vmts = {i: vmt for i, vmt in enumerate(vmts)}

    @staticmethod
    def class_chain(vmt):
        return [vmt]


class DfmTests(unittest.TestCase):
    def _stream(self):
        from delphinja.rtti import dfm

        prop = lambda name, value: (_short(name) + bytes([dfm.VA["vaIdent"]])
                                    + _short(value))
        child = (_short("TButton") + _short("Button1")
                 + prop("OnClick", "ButtonClick")
                 + prop("Align", "alClient") + b"\0" + b"\0")
        return (dfm.MAGIC + _short("TMainForm") + _short("MainForm")
                + prop("OnCreate", "FormCreate") + b"\0" + child + b"\0")

    def test_form_stream_decodes_nested_events_and_rejects_enums(self):
        from delphinja.rtti import dfm

        data = self._stream()
        root = dfm.parse_stream(memory_reader(data), 0x1000)

        self.assertEqual(root.class_name, "TMainForm")
        self.assertEqual(root.count(), 2)
        self.assertEqual([(node.name, prop.name, prop.value.value)
                          for node, prop in root.events()],
                         [("MainForm", "OnCreate", "FormCreate"),
                          ("Button1", "OnClick", "ButtonClick")])
        self.assertIsNone(
            dfm.parse_stream(memory_reader(data[:-1]), 0x1000))

    def test_duplicate_form_classes_are_resolved_by_handler_evidence(self):
        from delphinja.rtti import dfm

        root = dfm.parse_stream(memory_reader(self._stream()), 0x1000)
        weak = _Vmt("TMainForm", [{"name": "FormCreate", "addr": 0x2000}])
        strong = _Vmt("TMainForm", [
            {"name": "FormCreate", "addr": 0x3000},
            {"name": "ButtonClick", "addr": 0x3010},
        ])

        bindings, unresolved = dfm.bind(
            _Metadata([weak, strong]), [root], signatures=False)

        self.assertEqual(unresolved, [])
        self.assertEqual([(b.qualified, b.addr) for b in bindings],
                         [("TMainForm.FormCreate", 0x3000),
                          ("TMainForm.ButtonClick", 0x3010)])
        self.assertEqual(bindings[1].comment(),
                         "DFM: Button1: TButton.OnClick")


if __name__ == "__main__":
    unittest.main()
