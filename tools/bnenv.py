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


def seed_user_directory(scratch, plugin=None, settings=None):
    """Seed an isolated Binary Ninja user directory.

    Only the licence and the enterprise server URL are inherited from the
    real profile.  In particular, API keys, UI preferences, analysis limits
    and installed plugins never enter the scratch directory.  ``plugin`` may
    name one checkout to expose through the scratch plugin directory.

    This function deliberately does not import Binary Ninja.  Call it before
    starting the process which will use ``scratch``.
    """
    scratch = os.path.abspath(scratch)
    os.makedirs(scratch, mode=0o700, exist_ok=True)
    # A copied licence should not become readable merely because the caller's
    # umask is permissive or the scratch directory already existed.
    os.chmod(scratch, 0o700)
    for sub in ("plugins", "signatures"):
        os.makedirs(os.path.join(scratch, sub), mode=0o700, exist_ok=True)

    licence = os.path.join(REAL, "license.dat")
    target = os.path.join(scratch, "license.dat")
    if os.path.isfile(licence) and not os.path.exists(target):
        shutil.copyfile(licence, target)
        os.chmod(target, 0o600)

    settings_path = os.path.join(scratch, "settings.json")
    seeded = {}
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as fh:
                seeded = json.load(fh)
        except (OSError, ValueError):
            seeded = {}
    if "enterprise.server.url" not in seeded:
        try:
            with open(os.path.join(REAL, "settings.json")) as fh:
                real_settings = json.load(fh)
        except (OSError, ValueError):
            real_settings = {}
        url = real_settings.get("enterprise.server.url")
        if url:
            seeded["enterprise.server.url"] = url
    seeded.setdefault("corePlugins.warp", True)
    if settings:
        seeded.update(settings)
    with open(settings_path, "w") as fh:
        json.dump(seeded, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(settings_path, 0o600)

    if plugin is not None:
        plugin = os.path.realpath(plugin)
        link = os.path.join(scratch, "plugins", "delphinja")
        if os.path.lexists(link):
            if not os.path.islink(link) or os.path.realpath(link) != plugin:
                raise FileExistsError("plugin path is already occupied: %s" % link)
        else:
            os.symlink(plugin, link, target_is_directory=True)
    return scratch


def scratch_user_directory(default=None, plugin=None, settings=None):
    """Point BN_USER_DIRECTORY at a scratch directory and seed it.

    Copies the licence and carries over just the enterprise server URL; not
    the whole settings file, or the run inherits whatever analysis settings
    happen to be set interactively.
    """
    if default is None:
        default = os.path.join(tempfile.gettempdir(), "bn-build-home")
    os.environ.setdefault("BN_USER_DIRECTORY", default)
    return seed_user_directory(os.environ["BN_USER_DIRECTORY"], plugin,
                               settings)
