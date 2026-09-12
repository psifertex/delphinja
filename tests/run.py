#!/usr/bin/env python3
"""Run the tests with a disposable Binary Ninja profile.

The parent process creates and seeds the profile.  Tests execute in a child
using Binary Ninja's bundled Python, so all core/plugin state is gone before
the temporary directory (and its copied licence) is removed.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _darwin_installation():
    requested = os.environ.get("BN_TEST_APP")
    candidates = ([Path(requested)] if requested else []) + [
        Path("/Applications/Binary Ninja-enterprise-dev.app"),
        Path("/Applications/Binary Ninja-dev.app"),
        Path("/Applications/Binary Ninja.app"),
    ]
    for app in candidates:
        python = (app / "Contents/Frameworks/Python.framework/Versions/Current"
                  / "bin/python3")
        package = app / "Contents/Resources/python/binaryninja"
        home = app / "Contents/Resources/bundled-python3"
        if python.exists() and package.is_dir() and home.is_dir():
            return python, app / "Contents/Resources/python", home
    return None


def _interpreter():
    """Return (executable, Python package directory, PYTHONHOME or None)."""
    requested = os.environ.get("BN_TEST_PYTHON")
    if requested:
        package = os.environ.get("BN_TEST_PYTHONPATH", "")
        home = os.environ.get("BN_TEST_PYTHONHOME")
        return Path(requested), Path(package) if package else None, home
    if sys.platform == "darwin":
        result = _darwin_installation()
        if result:
            return result
    # Linux/Windows installations commonly configure their selected Python
    # directly.  The child will give a useful import error if that is not so.
    return Path(sys.executable), None, None


def _child(pattern, verbosity):
    suite = unittest.defaultTestLoader.discover(
        str(Path(__file__).parent), pattern=pattern, top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument(
        "--setting", action="append", default=[], metavar="KEY=JSON",
        help="override one setting in the disposable profile (repeatable)")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--isolated-child", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    verbosity = 1 if args.quiet else 2
    if args.isolated_child:
        return _child(args.pattern, verbosity)

    sys.path.insert(0, str(ROOT))
    from tools import bnenv

    if not Path(bnenv.REAL, "license.dat").is_file():
        parser.error("Binary Ninja's real user directory has no license.dat")

    settings = {
        "delphinja.commands": False,
        "delphinja.mechanism": "off",
        "delphinja.signatures": False,
        "network.enableUpdates": False,
    }
    for override in args.setting:
        key, separator, value = override.partition("=")
        if not separator or not key:
            parser.error("--setting must have the form KEY=JSON")
        try:
            settings[key] = json.loads(value)
        except json.JSONDecodeError as exc:
            parser.error("invalid JSON for %s: %s" % (key, exc))

    with tempfile.TemporaryDirectory(prefix="delphinja-tests-") as scratch:
        bnenv.seed_user_directory(scratch, plugin=ROOT, settings=settings)
        python, package, python_home = _interpreter()
        env = os.environ.copy()
        env["BN_USER_DIRECTORY"] = scratch
        env["DELPHINJA_REAL_USER_DIRECTORY"] = bnenv.REAL
        env["DELPHINJA_ROOT"] = str(ROOT)
        env.pop("BN_DISABLE_USER_PLUGINS", None)
        env.pop("BN_DISABLE_USER_SETTINGS", None)
        # Import the package through the installed-plugin symlink as Binary
        # Ninja does, not through the checkout's possibly renamed parent.
        paths = [str(Path(scratch, "plugins"))]
        if package:
            paths.insert(0, str(package))
        if env.get("PYTHONPATH"):
            paths.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(paths)
        if python_home:
            env["PYTHONHOME"] = str(python_home)
        command = [str(python), str(Path(__file__).resolve()),
                   "--isolated-child", "--pattern", args.pattern]
        if args.quiet:
            command.append("--quiet")
        return subprocess.run(command, cwd=ROOT, env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
