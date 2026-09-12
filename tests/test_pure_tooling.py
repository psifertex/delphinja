"""License-free tests for naming and evaluator correctness policy."""

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import bpleval, coalesce, evaluate, evalutil, fpceval, fpcname


class NamingTests(unittest.TestCase):
    def test_fpc_demangler_recovers_unit_class_member_and_hidden_self(self):
        name = fpcname.demangle(
            "SYSTEM$_$TOBJECT_$__$$_DESTROY", unit="SYSTEM")

        self.assertEqual(name.qualified(), "SYSTEM::TOBJECT::DESTROY")
        self.assertTrue(name.is_method)
        self.assertEqual(fpcname.hidden_params(name), (["self", "vmt"], []))

    def test_fpc_hashed_arguments_and_case_oracle_are_explicit(self):
        name = fpcname.demangle(
            "SYSUTILS_$$_FORMAT$crc6409A25D$$UNICODESTRING")
        oracle = fpcname.CaseOracle()
        oracle.add_bytes(b"SysUtils Format UnicodeString Format")

        self.assertTrue(name.hashed)
        self.assertEqual(name.ret, "UNICODESTRING")
        self.assertEqual(name.qualified(oracle), "SysUtils::Format")
        self.assertEqual(fpcname.hidden_params(name), ([], ["result"]))

    def test_name_vote_normalises_namespace_and_case_but_rejects_conflicts(self):
        claims = {
            "2009": "Classes::TObject::Free",
            "2014": "System.Classes::TObject::Free",
        }
        self.assertEqual(coalesce.vote(claims),
                         "System.Classes::TObject::Free")
        claims["2013"] = "System.Classes::TObject::Destroy"
        self.assertIsNone(coalesce.vote(claims))


class ValidationPolicyTests(unittest.TestCase):
    def test_errors_empty_inputs_and_low_correctness_fail_closed(self):
        self.assertEqual(
            evalutil.validation_problems(0, errors=1, passed=8, checked=10),
            ["1 input failed to process", "no inputs were processed",
             "correctness 80.00% is below 100.00%"])

    def test_allow_empty_and_report_only_are_explicit_opt_outs(self):
        self.assertEqual(evalutil.validation_problems(0, allow_empty=True), [])
        self.assertEqual(evalutil.exit_status(["bad"], report_only=True), 0)

    def test_relocation_bytes_are_the_only_fpc_differences_ignored(self):
        self.assertTrue(fpceval._same(b"abcdef", b"abXdef", {2}))
        self.assertFalse(fpceval._same(b"abcdef", b"abXdef", set()))
        self.assertFalse(fpceval._same(b"abc", b"abcd", {3}))

    def test_delphi_class_comparison_ignores_dots_inside_generics(self):
        self.assertEqual(
            evaluate.class_of(
                "TList<System.Classes.TComponent>.Add"),
            "TList<System.Classes.TComponent>")


class EvaluatorExitStatusTests(unittest.TestCase):
    def _corpus(self):
        temporary = tempfile.TemporaryDirectory(prefix="delphinja-eval-test-")
        Path(temporary.name, "sample.exe").touch()
        self.addCleanup(temporary.cleanup)
        return temporary.name

    def test_delphi_disagreement_is_failure_unless_report_only(self):
        result = {"file": "sample.exe", "size": 1, "functions": 5,
                  "matched": 2, "overlap": 2, "agree": 1,
                  "disagree": [("0x1", "TFoo.Bar", "Unit::TBaz::Bar")]}
        with mock.patch.object(evaluate, "evaluate", return_value=result), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evaluate.main([self._corpus()]), 1)
            self.assertEqual(evaluate.main(
                [self._corpus(), "--min-precision", "50"]), 0)
            self.assertEqual(evaluate.main(
                [self._corpus(), "--report-only"]), 0)

    def test_processing_error_is_failure(self):
        with mock.patch.object(evaluate, "evaluate",
                               side_effect=RuntimeError("broken")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evaluate.main([self._corpus()]), 1)

    def test_fpc_failed_byte_verification_is_failure(self):
        result = {"file": "sample.exe", "size": 1, "functions": 4,
                  "matched": 2, "checked": 2, "verified": 1, "wrong": []}
        with mock.patch.object(fpceval, "reference_index",
                               return_value=({}, None)), \
                mock.patch.object(fpceval, "evaluate", return_value=result), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fpceval.main(
                [self._corpus(), "--ref", "objects"]), 1)

    def test_bpl_name_disagreement_is_failure(self):
        rows = [(0x1000, "System::TObject::Free",
                 "System::TObject::Destroy")]
        with mock.patch.object(bpleval, "compare",
                               return_value=(4, {0x1000: object()}, rows)), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bpleval.main(["runtime.bpl", "rtl.warp"]), 1)


if __name__ == "__main__":
    unittest.main()
