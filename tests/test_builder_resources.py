"""Long-running signature builders close every BinaryView they acquire."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock


class _File(object):
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


class _View(object):
    def __init__(self, fail_analysis=False):
        self.file = _File()
        self.fail_analysis = fail_analysis

    def update_analysis_and_wait(self):
        if self.fail_analysis:
            raise RuntimeError("analysis failed")


class _Processor(object):
    def add_binary_view(self, _view):
        pass

    def start(self):
        raise RuntimeError("processor failed")


class _WarpFile(object):
    chunks = ()

    def to_data_buffer(self):
        return b"warp"


class _SuccessfulProcessor(_Processor):
    def start(self):
        return _WarpFile()


class BuilderResourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="delphinja-builder-resource-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def source(self, name="input.bin"):
        path = self.root / name
        path.write_bytes(b"input")
        return str(path)

    def test_rtti_harvest_closes_view_when_decoder_fails(self):
        from tools import rttigen

        view = _View()
        with mock.patch.object(rttigen.bn, "load", return_value=view), \
                mock.patch.object(rttigen, "_metadata",
                                  side_effect=RuntimeError("decoder failed")):
            with self.assertRaisesRegex(RuntimeError, "decoder failed"):
                rttigen.harvest(self.source())
        self.assertEqual(view.file.closed, 1)

    def test_rtti_generation_closes_contributed_views_on_warp_failure(self):
        from tools import rttigen

        source = self.source()
        view = _View()
        keep = {("Unit::TClass::Method", "guid"): [(source, 0x1000)]}
        chosen = [(source, {("Unit::TClass::Method", "guid"): 0x1000})]
        with mock.patch.object(rttigen.rttikb, "cover",
                               return_value=(chosen, {})), \
                mock.patch.object(rttigen, "contribute",
                                  return_value=(view, {
                                      "tagged": 1, "drifted": 0,
                                      "missing": 0})), \
                mock.patch.object(rttigen.warp, "WarpProcessor",
                                  return_value=_Processor()):
            with self.assertRaisesRegex(RuntimeError, "processor failed"):
                rttigen.generate(keep, str(self.root / "out.warp"))
        self.assertEqual(view.file.closed, 1)

    def test_rtti_contribution_closes_view_when_analysis_fails(self):
        from tools import rttigen

        view = _View(fail_analysis=True)
        with mock.patch.object(rttigen.bn, "load", return_value=view):
            with self.assertRaisesRegex(RuntimeError, "analysis failed"):
                rttigen.contribute(self.source(), {})
        self.assertEqual(view.file.closed, 1)

    def test_bpl_generation_closes_all_views_on_warp_failure(self):
        from tools import bplgen

        sources = [self.source("one.bpl"), self.source("two.bpl")]
        views = [_View(), _View()]
        readings = iter((view, []) for view in views)
        with mock.patch.object(bplgen, "candidates",
                               side_effect=lambda *_args: next(readings)), \
                mock.patch.object(bplgen, "apply", return_value=(0, 0)), \
                mock.patch.object(bplgen.warp, "WarpProcessor",
                                  return_value=_Processor()):
            with self.assertRaisesRegex(RuntimeError, "processor failed"):
                bplgen.generate(sources, str(self.root / "out.warp"),
                                prototypes=False)
        self.assertEqual([view.file.closed for view in views], [1, 1])

    def test_bpl_candidate_closes_view_when_analysis_fails(self):
        from tools import bplgen

        view = _View(fail_analysis=True)
        with mock.patch.object(bplgen.bplkb, "readings", return_value={}), \
                mock.patch.object(bplgen.bn, "load", return_value=view):
            with self.assertRaisesRegex(RuntimeError, "analysis failed"):
                bplgen.candidates(self.source("package.bpl"))
        self.assertEqual(view.file.closed, 1)

    def test_fpc_generation_closes_view_on_warp_failure(self):
        from tools import fpcgen

        source = self.source("unit.o")
        view = _View()
        with mock.patch.object(fpcgen, "object_files", return_value=[source]), \
                mock.patch.object(fpcgen, "case_oracle", return_value=None), \
                mock.patch.object(fpcgen, "build_view",
                                  return_value=(view, object())), \
                mock.patch.object(fpcgen.warp, "WarpProcessor",
                                  return_value=_Processor()):
            with self.assertRaisesRegex(RuntimeError, "processor failed"):
                fpcgen.generate([source], str(self.root / "work"),
                                str(self.root / "out.warp"), save_db=False)
        self.assertEqual(view.file.closed, 1)

    def test_idr_generation_closes_view_on_warp_failure(self):
        from tools import generate

        source = self.source("kb.bin")
        view = _View()
        with mock.patch.object(generate, "build_view",
                               return_value=(view, object())), \
                mock.patch.object(generate.warp, "WarpProcessor",
                                  return_value=_Processor()):
            with self.assertRaisesRegex(RuntimeError, "processor failed"):
                generate.generate(source, str(self.root / "work"),
                                  str(self.root / "out.warp"), save_db=False)
        self.assertEqual(view.file.closed, 1)

    def test_idr_generation_closes_view_after_successful_write(self):
        from tools import generate

        source = self.source("success-kb.bin")
        output = self.root / "success.warp"
        view = _View()
        with mock.patch.object(generate, "build_view",
                               return_value=(view, object())), \
                mock.patch.object(generate.warp, "WarpProcessor",
                                  return_value=_SuccessfulProcessor()):
            generate.generate(source, str(self.root / "success-work"),
                              str(output), save_db=False, log=lambda _msg: None)
        self.assertEqual(output.read_bytes(), b"warp")
        self.assertEqual(view.file.closed, 1)


if __name__ == "__main__":
    unittest.main()
