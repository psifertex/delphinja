"""Binary-Ninja-backed identity checks for the RTTI harvester."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock


class HarvestIdentityTests(unittest.TestCase):
    def test_same_corpus_tree_is_portable_between_checkouts(self):
        from tools import rttigen

        with tempfile.TemporaryDirectory(
                prefix="delphinja-harvest-identity-") as directory:
            identities = []
            for name in ("checkout-a", "checkout-b"):
                corpus = Path(directory, name, "corpus")
                binary = corpus / "project" / "sample.exe"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"same binary")
                with mock.patch.object(rttigen.bn, "core_version",
                                       return_value="test-core"):
                    identities.append(rttigen.harvest_identity(binary, corpus))
            self.assertEqual(identities[0], identities[1])


if __name__ == "__main__":
    unittest.main()
