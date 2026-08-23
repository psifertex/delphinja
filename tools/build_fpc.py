#!/usr/bin/env python3
"""Build a WARP signature library from a shipped Free Pascal release.

    python3 tools/build_fpc.py [outdir] [workdir] [versions]

Unattended and resumable, like `build_all.py`: each version/target is
independent, a failure is logged and the run moves on, and anything already
built is skipped.

Where the inputs come from
--------------------------
A Free Pascal release ships the compiled RTL as `.o` objects next to the
`.ppu` metadata, and on Windows the compiler puts every routine in its own
`.text.n_<mangled name>` section (`tf_smartlink_sections` is unconditional
there).  So the release itself is the knowledge base: name, exact bytes and an
authoritative relocation table per routine, with no compiler installation and
nothing to build.

The Windows installers are Inno Setup archives, which `innoextract` unpacks on
any platform.  That is the only external tool this needs, and only when the
unit tree is not already on disk.

Coverage
--------
FPC 3.2.2 (May 2021) is still the current stable release, and every Lazarus
from 2.2.0 (Jan 2022) to 4.8 (Jun 2026) bundles it -- so one library covers
most FPC binaries in the wild, with 3.0.4 and 2.6.4 for older ones.

The `rtl*` packages are what a library targets: they are what every FPC binary
links, they are what the corpus is full of, and the full 1255-object unit tree
stages 113,738 routines, which is both a much longer analysis and a much
larger image (WARP masks constants that land inside the mapped extent, so an
oversized image changes how functions hash).
"""

import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ROOT, not its parent: importing `delphinja` would execute the plugin's
# __init__ and register the recovery workflow inside this process, which would
# then run against the staged signature image and remove functions from it.
sys.path.insert(0, ROOT)

from tools import bnenv        # noqa: E402  (before any binaryninja import)

bnenv.scratch_user_directory("/tmp/bn-fpc-build")

# (version, target) -> installer path under the SourceForge Win32 tree. There
# is no native win64 installer: the compiler that builds win64 units is itself
# a win32 binary, so the win64 unit tree ships inside a win32 installer.
INSTALLERS = {
    ("3.2.2", "i386-win32"): "Win32/3.2.2/fpc-3.2.2.i386-win32.exe",
    ("3.0.4", "i386-win32"): "Win32/3.0.4/fpc-3.0.4.i386-win32.exe",
    ("2.6.4", "i386-win32"): "Win32/2.6.4/fpc-2.6.4.i386-win32.exe",
    # The combined installer, not `.cross.x86_64-win64.exe`: the cross
    # installer is not Inno Setup and innoextract cannot read it, while the
    # combined one carries both unit trees and unpacks normally.
    ("3.2.2", "x86_64-win64"): "Win32/3.2.2/fpc-3.2.2.win32.and.win64.exe",
}

BASE_URL = "https://sourceforge.net/projects/freepascal/files/%s/download"

PLATFORMS = {"i386-win32": "windows-x86", "x86_64-win64": "windows-x86_64"}

# Which package directories a library covers. Prefixes, matched against the
# directory name under units/<target>/.
PACKAGES = ("rtl",)

TARGETS = [("3.2.2", "i386-win32"), ("3.0.4", "i386-win32"),
           ("2.6.4", "i386-win32"), ("3.2.2", "x86_64-win64")]


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def unit_dirs(tree, target):
    """The package directories a library should cover, if the tree has them."""
    base = os.path.join(tree, "units", target)
    if not os.path.isdir(base):
        return []
    return [os.path.join(base, d) for d in sorted(os.listdir(base))
            if d.startswith(PACKAGES) and os.path.isdir(os.path.join(base, d))]


def fetch(version, target, cache):
    """Extract the release's unit tree, downloading the installer if needed."""
    member = INSTALLERS.get((version, target))
    if member is None:
        raise RuntimeError("no installer known for FPC %s %s" % (version, target))
    name = os.path.basename(member)
    root = os.path.join(cache, name[:-len(".exe")])
    tree = os.path.join(root, "app")
    if unit_dirs(tree, target):
        return tree
    archive = os.path.join(cache, name)
    if not os.path.exists(archive):
        log("downloading %s" % name)
        urllib.request.urlretrieve(BASE_URL % member, archive)
        # SourceForge answers a 502 with an HTML page and curl-like tools save
        # it happily; an installer that is not a PE is that page.
        with open(archive, "rb") as fh:
            if fh.read(2) != b"MZ":
                os.unlink(archive)
                raise RuntimeError("%s is not an executable; the download was "
                                   "probably an error page" % name)
    log("extracting %s" % name)
    subprocess.run(["innoextract", "-s", "-d", root, archive],
                   check=True, capture_output=True)
    if not unit_dirs(tree, target):
        raise RuntimeError("no units/%s in the extracted tree" % target)
    return tree


def main(outdir, workdir, only=None):
    os.makedirs(outdir, exist_ok=True)
    cache = os.path.join(workdir, "releases")
    os.makedirs(cache, exist_ok=True)

    from tools import fpcgen

    results = []
    started = time.time()
    for version, target in TARGETS:
        tag = "%s-%s" % (version, target.split("-")[-1])
        if only and version not in only and tag not in only:
            continue
        out = os.path.join(outdir, "fpc-rtl-%s.warp" % tag)
        if os.path.exists(out):
            log("%s already built, skipping" % tag)
            results.append((tag, "skipped", os.path.getsize(out), 0))
            continue
        t0 = time.time()
        try:
            tree = fetch(version, target, cache)
            roots = unit_dirs(tree, target)
            log("%s: %d package directories" % (tag, len(roots)))
            fpcgen.generate(roots, os.path.join(workdir, "build-%s" % tag),
                            out, platform=PLATFORMS[target], log=log)
            results.append((tag, "built", os.path.getsize(out),
                            time.time() - t0))
        except Exception as exc:                            # noqa: BLE001
            log("%s FAILED: %s" % (tag, exc))
            results.append((tag, "failed: %s" % exc, 0, time.time() - t0))

    print("\n%-18s %-12s %12s %8s" % ("target", "status", "bytes", "minutes"))
    for tag, status, size, secs in results:
        print("%-18s %-12s %12d %8.1f" % (tag, status[:12], size, secs / 60))
    log("total %.1f minutes" % ((time.time() - started) / 60))


if __name__ == "__main__":
    import binaryninja
    binaryninja.disable_default_log()
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "signatures"),
         sys.argv[2] if len(sys.argv) > 2 else "/tmp/fpc-warp-build",
         sys.argv[3].split(",") if len(sys.argv) > 3 else None)
