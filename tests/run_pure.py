#!/usr/bin/env python3
"""Run the license-free test subset used by CI."""

from pathlib import Path
import unittest


def main():
    root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(
        str(Path(__file__).parent), pattern="test_pure*.py",
        top_level_dir=str(root))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
