#!/usr/bin/env python3
"""Build a WARP signature library for every Delphi version IDR ships a knowledge base for.

    python3 build_all.py [outdir] [workdir]

Designed to be started and left alone. Each version is independent: a failure
is logged and the run moves on, and anything already built is skipped, so
re-running after an interruption picks up where it stopped rather than starting
over.

Knowledge bases are named by their own tag rather than by a product name.
`kb2011` through `kb2014` correspond to the XE series, but the mapping from
knowledge base to product is not documented anywhere authoritative, and a
signature library labelled with the wrong Delphi version would be worse than
one labelled with the tag it actually came from.
"""

import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)             # the plugin package

# Scratch Binary Ninja user directory. Set before binaryninja is imported so a
# batch run cannot write to the real one -- Settings() writes are global.
os.environ.setdefault("BN_USER_DIRECTORY", "/tmp/bn-build-home")
for sub in ("", "/plugins", "/signatures"):
    os.makedirs(os.environ["BN_USER_DIRECTORY"] + sub, exist_ok=True)


def _seed_scratch_user_directory():
    """Give the scratch directory the minimum it needs to start.

    An isolated user directory has no licence and no enterprise server, and
    binaryninja fails at load with "Unknown Enterprise Server URL" rather than
    at import -- so an unattended run gets through staging and dies on the
    first analysis. Copy the licence and carry over just the server URL; do
    not copy the whole settings file, or the run inherits whatever analysis
    settings happen to be set interactively.
    """
    import json
    import shutil
    scratch = os.environ["BN_USER_DIRECTORY"]
    real = os.path.expanduser("~/Library/Application Support/Binary Ninja")
    licence = os.path.join(real, "license.dat")
    if os.path.exists(licence) and not os.path.exists(os.path.join(scratch, "license.dat")):
        shutil.copy2(licence, os.path.join(scratch, "license.dat"))
    settings_path = os.path.join(scratch, "settings.json")
    settings = {}
    if os.path.exists(settings_path):
        try:
            settings = json.load(open(settings_path))
        except Exception:
            settings = {}
    if "enterprise.server.url" not in settings:
        try:
            real_settings = json.load(open(os.path.join(real, "settings.json")))
        except Exception:
            real_settings = {}
        url = real_settings.get("enterprise.server.url")
        if url:
            settings["enterprise.server.url"] = url
    settings.setdefault("corePlugins.warp", True)
    json.dump(settings, open(settings_path, "w"), indent=2)


_seed_scratch_user_directory()

KB_TAGS = ["2", "3", "4", "5", "6", "7",
           "2005", "2006", "2007", "2009", "2010",
           "2011", "2012", "2013", "2014"]

KB_URL = "https://github.com/crypto2011/IDR/raw/master/kb%s.7z"


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def fetch(tag, cache):
    archive = os.path.join(cache, "kb%s.7z" % tag)
    if not os.path.exists(archive):
        log("downloading kb%s" % tag)
        urllib.request.urlretrieve(KB_URL % tag, archive)
    target = os.path.join(cache, "kb%s" % tag)
    binfile = os.path.join(target, "kb%s.bin" % tag)
    if not os.path.exists(binfile):
        log("extracting kb%s" % tag)
        subprocess.run(["7z", "x", "-y", archive, "-o" + target],
                       check=True, capture_output=True)
    if not os.path.exists(binfile):
        # Some archives name the member differently; take the only .bin.
        found = [f for f in os.listdir(target) if f.endswith(".bin")]
        if not found:
            raise RuntimeError("no .bin inside kb%s.7z" % tag)
        binfile = os.path.join(target, found[0])
    return binfile


def main(outdir, workdir, only=None):
    tags = [t for t in KB_TAGS if not only or t in only]
    os.makedirs(outdir, exist_ok=True)
    cache = os.path.join(workdir, "kb")
    os.makedirs(cache, exist_ok=True)

    from tools import generate

    results = []
    started = time.time()
    for tag in tags:
        out = os.path.join(outdir, "delphi-rtl-%s.warp" % tag)
        if os.path.exists(out):
            log("kb%s already built, skipping" % tag)
            results.append((tag, "skipped", os.path.getsize(out), 0))
            continue
        t0 = time.time()
        try:
            binfile = fetch(tag, cache)
            work = os.path.join(workdir, "build%s" % tag)
            generate.generate(binfile, work, out, save_db=True, log=log)
            results.append((tag, "built", os.path.getsize(out), time.time() - t0))
        except Exception as exc:
            log("kb%s FAILED: %s" % (tag, exc))
            results.append((tag, "failed: %s" % exc, 0, time.time() - t0))

    print("\n%-8s %-10s %12s %8s" % ("version", "status", "bytes", "minutes"))
    for tag, status, size, secs in results:
        print("%-8s %-10s %12d %8.1f" % (tag, status[:10], size, secs / 60))
    log("total %.1f minutes" % ((time.time() - started) / 60))


if __name__ == "__main__":
    # ROOT, not its parent: importing `delphi` would execute the plugin's
    # __init__ and register the recovery workflow inside this process, which
    # would then run against the staged signature image and remove functions
    # from it. `tools` has no such side effects.
    sys.path.insert(0, ROOT)
    import binaryninja
    binaryninja.disable_default_log()
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "signatures"),
         sys.argv[2] if len(sys.argv) > 2 else "/tmp/delphi-warp-build",
         sys.argv[3].split(",") if len(sys.argv) > 3 else None)
