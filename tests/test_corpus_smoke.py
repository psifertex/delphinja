"""Opt-in real-binary check; skipped unless tests/run.py selects a PE."""

import os
from pathlib import Path
import unittest


class CorpusSmokeTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("DELPHINJA_CORPUS_SMOKE"),
                         "pass --corpus-smoke to run a real PE")
    def test_metadata_recovery_and_application_on_real_pe(self):
        import binaryninja as bn
        from delphinja.rtti import apply

        path = Path(os.environ["DELPHINJA_CORPUS_SMOKE"])
        view = bn.load(str(path), update_analysis=True,
                       options={"analysis.debugInfo.internal": False})
        self.assertIsNotNone(view, "Binary Ninja could not open %s" % path)
        try:
            view.update_analysis_and_wait()
            metadata = apply.DelphiMetadata(view).scan(scan_dfm=True)
            self.assertTrue(metadata.vmts,
                            "%s contained no recoverable Delphi VMTs" % path)
            stats = apply.Applier(metadata, {"undefine": False}).run()
            self.assertGreater(stats.get("structs", 0) +
                               stats.get("enums", 0) +
                               stats.get("functions_named", 0), 0)
        finally:
            view.file.close()


if __name__ == "__main__":
    unittest.main()
