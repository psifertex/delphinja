"""Keep a batch build out of the user's real Binary Ninja configuration.

`Settings()` writes are global and a signature build runs unattended for
hours, so every entry point here points BN_USER_DIRECTORY at a scratch
directory first.  An isolated directory has no licence and no enterprise
server, and binaryninja then fails at *load* with "Unknown Enterprise Server
URL" rather than at import -- so an unattended run gets all the way through
staging and dies on the first analysis.  Seeding is what prevents that.

Import this before `binaryninja`.
"""

import json
import os
import shutil
import sys
import tempfile


def real_user_directory():
    """Binary Ninja's own user directory for this platform.

    Resolved here rather than asked of the API, because the point of this
    module is to redirect BN_USER_DIRECTORY *before* binaryninja is imported.
    """
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Binary Ninja")
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(base, "Binary Ninja")
    return os.path.expanduser("~/.binaryninja")


REAL = real_user_directory()


def scratch_user_directory(default=None):
    """Point BN_USER_DIRECTORY at a scratch directory and seed it.

    Copies the licence and carries over just the enterprise server URL; not
    the whole settings file, or the run inherits whatever analysis settings
    happen to be set interactively.
    """
    if default is None:
        default = os.path.join(tempfile.gettempdir(), "bn-build-home")
    os.environ.setdefault("BN_USER_DIRECTORY", default)
    scratch = os.environ["BN_USER_DIRECTORY"]
    for sub in ("", "plugins", "signatures"):
        os.makedirs(os.path.join(scratch, sub), exist_ok=True)

    licence = os.path.join(REAL, "license.dat")
    target = os.path.join(scratch, "license.dat")
    if os.path.exists(licence) and not os.path.exists(target):
        shutil.copy2(licence, target)

    settings_path = os.path.join(scratch, "settings.json")
    settings = {}
    if os.path.exists(settings_path):
        try:
            settings = json.load(open(settings_path))
        except Exception:
            settings = {}
    if "enterprise.server.url" not in settings:
        try:
            real_settings = json.load(open(os.path.join(REAL, "settings.json")))
        except Exception:
            real_settings = {}
        url = real_settings.get("enterprise.server.url")
        if url:
            settings["enterprise.server.url"] = url
    settings.setdefault("corePlugins.warp", True)
    json.dump(settings, open(settings_path, "w"), indent=2)
    return scratch
