import unittest
from unittest import mock


class _File(object):
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


class _View(object):
    def __init__(self, fail=False):
        self.file = _File()
        self.functions = []
        self.fail = fail

    def update_analysis_and_wait(self):
        if self.fail:
            raise RuntimeError("analysis failed")


class EvaluatorResourceTests(unittest.TestCase):
    def test_delphi_no_rtti_path_closes_view(self):
        from delphinja.rtti import apply
        from tools import evaluate

        view = _View()
        metadata = mock.Mock(vmts={})
        with mock.patch.object(evaluate, "_load_view", return_value=view), \
                mock.patch.object(apply, "DelphiMetadata") as factory, \
                mock.patch.object(evaluate.os.path, "getsize", return_value=1):
            factory.return_value.scan.return_value = metadata
            result = evaluate.evaluate("sample.exe")

        self.assertEqual(result["rtti"], 0)
        self.assertEqual(view.file.closed, 1)

    def test_analysis_failure_closes_delphi_and_fpc_views(self):
        from tools import evaluate, fpceval

        for module in (evaluate, fpceval):
            view = _View(fail=True)
            with self.subTest(module=module.__name__), \
                    mock.patch.object(module, "_load_view", return_value=view), \
                    mock.patch.object(module.os.path, "getsize", return_value=1):
                with self.assertRaises(RuntimeError):
                    module.evaluate("sample.exe")
                self.assertEqual(view.file.closed, 1)

    def test_bpl_comparison_closes_view(self):
        from binaryninja import warp
        from tools import bpleval, bplkb

        view = _View()
        container = mock.Mock()
        with mock.patch.object(warp.WarpContainer, "add",
                               return_value=container), \
                mock.patch.object(bplkb, "readings", return_value={}), \
                mock.patch.object(bpleval, "_load_view", return_value=view):
            functions, claims, rows = bpleval.compare("runtime.bpl", "rtl.warp")

        self.assertEqual((functions, claims, rows), (0, {}, []))
        self.assertEqual(view.file.closed, 1)


if __name__ == "__main__":
    unittest.main()
