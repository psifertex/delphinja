"""License-free checks for provenance, content caches, and atomic writes."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import repro


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="delphinja-repro-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_size_hash_and_git_blob_verification(self):
        source = self.root / "source.bin"
        source.write_bytes(b"hello\n")
        self.assertTrue(repro.verify_file(source, {
            "size": 6,
            "sha256": hashlib.sha256(b"hello\n").hexdigest(),
            "git_blob_sha1": "ce013625030ba8dba906f756967f9e9ca394464a",
        }))
        self.assertFalse(repro.verify_file(source, {"size": 7}))
        self.assertFalse(repro.verify_file(source, {"sha256": "0" * 64}))

    def test_verified_download_replaces_atomically_and_reuses_good_cache(self):
        destination = self.root / "download.bin"
        destination.write_bytes(b"old")
        expected = {"size": 3, "sha256": hashlib.sha256(b"new").hexdigest()}
        calls = []

        def retrieve(url, temporary):
            calls.append((url, temporary))
            self.assertEqual(destination.read_bytes(), b"old")
            Path(temporary).write_bytes(b"new")

        repro.fetch_verified("https://invalid.test/input", destination,
                             expected, retrieve)
        self.assertEqual(destination.read_bytes(), b"new")
        self.assertNotEqual(calls[0][1], str(destination))
        repro.fetch_verified("https://invalid.test/input", destination,
                             expected, retrieve)
        self.assertEqual(len(calls), 1)

    def test_failed_download_does_not_replace_previous_cache(self):
        destination = self.root / "download.bin"
        destination.write_bytes(b"old")

        def retrieve(_url, temporary):
            Path(temporary).write_bytes(b"bad")

        with self.assertRaises(repro.VerificationError):
            repro.fetch_verified(
                "https://invalid.test/input", destination,
                {"size": 4, "sha256": hashlib.sha256(b"good").hexdigest()},
                retrieve)
        self.assertEqual(destination.read_bytes(), b"old")


class CacheIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="delphinja-cache-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tool = self.root / "tools" / "decoder.py"
        self.tool.parent.mkdir()
        self.tool.write_text("VERSION = 1\n")

    def identity(self, source):
        return repro.content_cache_manifest(
            "harvest", source, self.root / "corpus", [self.tool],
            self.root / "tools", {"option": False}, {"engine": "1"})

    def test_same_basename_in_different_projects_has_a_distinct_key(self):
        left = self.root / "corpus" / "left" / "sample.exe"
        right = self.root / "corpus" / "right" / "sample.exe"
        left.parent.mkdir(parents=True)
        right.parent.mkdir(parents=True)
        left.write_bytes(b"same")
        right.write_bytes(b"same")
        self.assertNotEqual(repro.manifest_stamp(self.identity(left)),
                            repro.manifest_stamp(self.identity(right)))

    def test_content_and_tool_changes_invalidate_the_cache(self):
        source = self.root / "corpus" / "project" / "sample.exe"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"one")
        first = self.identity(source)
        source.write_bytes(b"two")
        second = self.identity(source)
        self.tool.write_text("VERSION = 2\n")
        third = self.identity(source)
        self.assertNotEqual(repro.manifest_stamp(first),
                            repro.manifest_stamp(second))
        self.assertNotEqual(repro.manifest_stamp(second),
                            repro.manifest_stamp(third))

    def test_cache_document_rejects_corruption_and_the_wrong_build(self):
        source = self.root / "corpus" / "sample.exe"
        source.parent.mkdir()
        source.write_bytes(b"binary")
        build = self.identity(source)
        path = repro.cache_path(self.root / "cache", source, build)
        repro.write_cache(path, build, {"answer": 42})
        self.assertEqual(repro.read_cache(path, build), {"answer": 42})
        other = dict(build, settings={"option": True})
        self.assertIsNone(repro.read_cache(path, other))
        document = json.loads(Path(path).read_text())
        document["record"]["answer"] = 43
        Path(path).write_text(json.dumps(document))
        self.assertIsNone(repro.read_cache(path, build))
        Path(path).write_text("not json")
        self.assertIsNone(repro.read_cache(path, build))

    def test_identical_trees_have_portable_stable_manifests(self):
        manifests = []
        for directory in ("checkout-a", "checkout-b"):
            root = self.root / directory
            source = root / "corpus" / "project" / "sample.exe"
            tool = root / "tools" / "decoder.py"
            source.parent.mkdir(parents=True)
            tool.parent.mkdir(parents=True)
            source.write_bytes(b"binary")
            tool.write_text("VERSION = 1\n")
            manifests.append(repro.content_cache_manifest(
                "harvest", source, root / "corpus", [tool], root / "tools",
                {"option": False}, {"engine": "1"}))
        self.assertEqual(manifests[0], manifests[1])
        self.assertEqual(repro.canonical_json(manifests[0]),
                         repro.canonical_json(manifests[1]))

    def test_extracted_tree_inventory_detects_content_changes(self):
        tree = self.root / "release"
        obj = tree / "rtl" / "unit.o"
        ppu = tree / "rtl" / "unit.ppu"
        obj.parent.mkdir(parents=True)
        obj.write_bytes(b"object")
        ppu.write_bytes(b"metadata")
        expected = repro.file_inventory([obj, ppu], tree)
        self.assertTrue(repro.inventory_matches([ppu, obj], expected, tree))
        obj.write_bytes(b"changed")
        self.assertFalse(repro.inventory_matches([obj, ppu], expected, tree))


class ArtifactManifestTests(unittest.TestCase):
    def test_manifest_is_stable_and_detects_artifact_corruption(self):
        with tempfile.TemporaryDirectory(
                prefix="delphinja-artifact-test-") as directory:
            artifact = Path(directory) / "library.warp"
            artifact.write_bytes(b"warp")
            build = repro.build_manifest(
                "test", [{"b": 2, "a": 1}], {"z": False}, [])
            first = repro.write_artifact_manifest(artifact, build)
            second = repro.artifact_manifest(artifact, build)
            self.assertEqual(first, second)
            self.assertTrue(repro.artifact_is_current(artifact, build))
            artifact.write_bytes(b"changed")
            self.assertFalse(repro.artifact_is_current(artifact, build))

    def test_coalesce_help_runs_as_a_direct_script(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, str(root / "tools" / "coalesce.py"), "--help"],
            cwd=root, env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Coalesce the shipped Delphi libraries", result.stdout)


if __name__ == "__main__":
    unittest.main()
