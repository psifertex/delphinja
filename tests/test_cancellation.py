import os
import tempfile
import types
import unittest
from unittest import mock

from tests.support import memory_reader


class ScannerCancellationTests(unittest.TestCase):
    def test_rtti_scanner_raises_instead_of_returning_a_partial_prefix(self):
        from delphinja.rtti import parser

        reader = memory_reader(bytes(0x400), base=0x1000)
        with self.assertRaises(parser.ScanCancelled):
            parser.scan(reader, 0x1000, 0x1400,
                        lambda _done, _total: False)

    def test_later_string_and_reference_passes_observe_cancellation(self):
        from delphinja.rtti import parser

        data = bytes(parser._CHUNK + 8)
        reader = memory_reader(data, base=0x2000)
        passes = (
            lambda cb: list(parser.scan_strings(
                reader, 0x2000, 0x2000 + len(data), progress=cb)),
            lambda cb: list(parser.headerless_candidates(
                reader, 0x2000, 0x2000 + len(data), progress=cb)),
            lambda cb: parser.pointer_targets(
                reader, [(0x2000, 0x2000 + len(data))], [0x1234],
                progress=cb),
        )
        for run in passes:
            with self.subTest(run=run), self.assertRaises(
                    parser.ScanCancelled):
                run(lambda _done, _total: False)

    def test_layout_and_dfm_passes_observe_cancellation(self):
        from delphinja.rtti import dfm, parser

        reader = memory_reader(bytes(0x100), base=0x3000)
        callback = lambda _done, _total: False
        with self.assertRaises(parser.ScanCancelled):
            parser.detect_layout(reader, [(0x3000, 0x3100)],
                                 ptr_sizes=(4,), progress=callback)
        with self.assertRaises(parser.ScanCancelled):
            dfm.find_streams(reader, [(0x3000, 0x3100)], callback)


class MetadataCancellationTests(unittest.TestCase):
    @staticmethod
    def _metadata():
        from delphinja.rtti.apply import DelphiMetadata

        metadata = DelphiMetadata.__new__(DelphiMetadata)
        metadata.bv = types.SimpleNamespace(
            sections={}, segments=[], start=0x1000, end=0x2100)
        metadata.reader = mock.sentinel.reader
        metadata._code_ranges = [(0x1000, 0x1100), (0x2000, 0x2100)]
        metadata.vmts = {0x10: types.SimpleNamespace(
            header=0x10, vtable_end=0x14, name="Old", regions=[])}
        metadata.typeinfos = {0x20: types.SimpleNamespace(
            ptr_addr=0x1c, addr=0x20, end=0x24, name="Old")}
        metadata.strings = {0x30: types.SimpleNamespace(
            addr=0x30, end=0x34, kind="AnsiString")}
        metadata.char_arrays = {0x40: types.SimpleNamespace(
            addr=0x40, end=0x44, kind="PChar")}
        metadata.dfm_streams = [mock.sentinel.old_form]
        metadata._children = mock.sentinel.children
        metadata._interfaces = mock.sentinel.interfaces
        metadata._uregions = mock.sentinel.regions
        metadata._uevidence = mock.sentinel.evidence
        metadata._class_ti = mock.sentinel.class_ti
        return metadata

    @staticmethod
    def _state(metadata):
        return (metadata.vmts, metadata.typeinfos, metadata.strings,
                metadata.char_arrays, metadata.dfm_streams,
                metadata._children, metadata._interfaces,
                metadata._uregions, metadata._uevidence,
                metadata._class_ti)

    def test_cancelling_a_later_range_rolls_back_earlier_results(self):
        from delphinja.rtti import apply, parser

        metadata = self._metadata()
        before = self._state(metadata)
        with mock.patch.object(apply.P, "scan", side_effect=[
                ({0x1000: mock.sentinel.new_vmt}, {}),
                parser.ScanCancelled()]), \
                mock.patch.object(apply.P, "scan_strings", return_value=[]):
            with self.assertRaises(parser.ScanCancelled):
                metadata.scan(progress=lambda _done, _total: True)

        self.assertEqual(self._state(metadata), before)
        self.assertIs(metadata.vmts, before[0])

    def test_cancelling_optional_dfm_scan_rolls_back_all_staged_results(self):
        from delphinja.rtti import apply, parser

        metadata = self._metadata()
        before = self._state(metadata)
        with mock.patch.object(apply.P, "scan", return_value=({}, {})), \
                mock.patch.object(apply.P, "scan_strings", return_value=[]), \
                mock.patch.object(apply.P, "scan_headerless_strings",
                                  return_value=[]), \
                mock.patch.object(apply.dfm, "find_streams",
                                  side_effect=parser.ScanCancelled()):
            with self.assertRaises(parser.ScanCancelled):
                metadata.scan([(0x1000, 0x1100)], scan_dfm=True)

        self.assertEqual(self._state(metadata), before)

    def test_completed_scan_commits_staged_results_and_dfm_together(self):
        from delphinja.rtti import apply

        metadata = self._metadata()
        literal = types.SimpleNamespace(
            addr=0x80, end=0x88, kind="PChar")
        with mock.patch.object(apply.P, "scan", return_value=({}, {})), \
                mock.patch.object(apply.P, "scan_strings", return_value=[]), \
                mock.patch.object(apply.P, "scan_headerless_strings",
                                  return_value=[literal]), \
                mock.patch.object(apply.dfm, "find_streams",
                                  return_value=[mock.sentinel.new_form]):
            result = metadata.scan(
                [(0x1000, 0x1100)],
                progress=lambda _done, _total: True, scan_dfm=True)

        self.assertIs(result, metadata)
        self.assertIs(metadata.char_arrays[literal.addr], literal)
        self.assertEqual(metadata.dfm_streams, [mock.sentinel.new_form])
        self.assertIsNone(metadata._children)


class _CancelledTask(object):
    """Run a command body now, with its scan cancelled before publication."""

    scans = []

    def __init__(self, bv, title, fn):
        self.bv = bv
        self.progress = title
        self.fn = fn

    def scan(self, *args, **kwargs):
        from delphinja.rtti.parser import ScanCancelled
        self.scans.append((args, kwargs))
        raise ScanCancelled()

    def start(self):
        from delphinja.rtti.parser import ScanCancelled
        try:
            self.fn(self)
        except ScanCancelled:
            pass


class CommandCancellationTests(unittest.TestCase):
    def test_cancelled_commands_publish_nothing(self):
        import delphinja as plugin

        view = mock.Mock()
        _CancelledTask.scans = []
        with tempfile.TemporaryDirectory() as scratch:
            export_path = os.path.join(scratch, "metadata.json")
            with mock.patch.object(plugin, "_Task", _CancelledTask), \
                    mock.patch.object(plugin, "get_choice_input",
                                      return_value=0), \
                    mock.patch.object(plugin, "get_save_filename_input",
                                      return_value=export_path), \
                    mock.patch.object(plugin.A, "setting", return_value=True), \
                    mock.patch.object(plugin.A, "Applier") as applier, \
                    mock.patch.object(plugin, "show_message_box") as show, \
                    mock.patch.object(plugin.bn, "log_info") as log_info:
                plugin.cmd_report(view)
                plugin.cmd_apply(view)
                plugin.cmd_scan_range(view, 0x1000, 0x20)
                plugin.cmd_export(view)

            view.show_markdown_report.assert_not_called()
            view.update_analysis.assert_not_called()
            applier.assert_not_called()
            show.assert_not_called()
            log_info.assert_not_called()
            self.assertFalse(os.path.exists(export_path))
            self.assertEqual(_CancelledTask.scans, [
                ((), {}),
                ((), {"scan_dfm": True}),
                (([(0x1000, 0x1020)],), {"scan_dfm": True}),
                ((), {}),
            ])

    def test_apply_skips_the_dfm_pass_when_the_setting_is_disabled(self):
        import delphinja as plugin

        _CancelledTask.scans = []
        with mock.patch.object(plugin, "_Task", _CancelledTask), \
                mock.patch.object(plugin, "get_choice_input", return_value=0), \
                mock.patch.object(plugin.A, "setting", return_value=False):
            plugin.cmd_apply(mock.Mock())

        self.assertEqual(_CancelledTask.scans,
                         [((), {"scan_dfm": False})])

    def test_undefine_only_skips_the_unused_dfm_pass(self):
        import delphinja as plugin

        _CancelledTask.scans = []
        with mock.patch.object(plugin, "_Task", _CancelledTask), \
                mock.patch.object(plugin, "get_choice_input", return_value=2), \
                mock.patch.object(plugin.A, "setting", return_value=True):
            plugin.cmd_apply(mock.Mock())

        self.assertEqual(_CancelledTask.scans,
                         [((), {"scan_dfm": False})])

    def test_background_task_treats_cancellation_as_a_normal_outcome(self):
        import delphinja as plugin

        def cancel(_task):
            raise plugin.P.ScanCancelled()

        task = types.SimpleNamespace(fn=cancel, progress="scanning")
        with mock.patch.object(plugin.bn, "log_error") as log_error:
            plugin._Task.run(task)
        log_error.assert_not_called()


class DebugInfoCancellationTests(unittest.TestCase):
    def test_cancelled_parse_contributes_and_registers_nothing(self):
        from delphinja.integration import debuginfo
        from delphinja.rtti import parser

        view = types.SimpleNamespace(
            arch=types.SimpleNamespace(address_size=4))
        metadata = mock.Mock()
        metadata.scan.side_effect = parser.ScanCancelled()
        with mock.patch.object(debuginfo.signatures, "fpc_version",
                              return_value=None), \
                mock.patch.object(debuginfo.A, "DelphiMetadata",
                                  return_value=metadata), \
                mock.patch.object(debuginfo.signatures,
                                  "register_delphi") as register_delphi, \
                mock.patch.object(debuginfo.signatures,
                                  "register_fpc") as register_fpc, \
                mock.patch.object(debuginfo.sinks,
                                  "DebugInfoSink") as sink, \
                mock.patch.object(debuginfo.A, "Applier") as applier, \
                mock.patch.object(debuginfo.bn, "log_error") as log_error, \
                mock.patch.object(debuginfo.bn, "log_info") as log_info:
            result = debuginfo.parse_info(
                mock.sentinel.debug_info, view, None,
                lambda _done, _total: False)

        self.assertFalse(result)
        register_delphi.assert_not_called()
        register_fpc.assert_not_called()
        sink.assert_not_called()
        applier.assert_not_called()
        log_error.assert_not_called()
        log_info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
