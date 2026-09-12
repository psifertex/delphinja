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
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)             # the plugin package

# ROOT, not its parent: importing `delphinja` would execute the plugin's
# __init__ and register the recovery workflow inside this process, which would
# then run against the staged signature image and remove functions from it.
# `tools` has no such side effects.
sys.path.insert(0, ROOT)

from tools import bnenv       # noqa: E402  (must precede any binaryninja import)
from tools import repro       # noqa: E402

# Scratch Binary Ninja user directory, seeded so an unattended run can start.
# Set before binaryninja is imported: Settings() writes are global.
bnenv.scratch_user_directory()

KB_TAGS = ["2", "3", "4", "5", "6", "7",
           "2005", "2006", "2007", "2009", "2010",
           "2011", "2012", "2013", "2014"]

# Immutable IDR source revision.  ``git_blob_sha1`` values come from GitHub's
# content API at this revision; unlike a branch URL they authenticate exactly
# the bytes that the repository commit names.
IDR_REVISION = "03f38fc0b2e5b972c644e0c80a24872c447aa5b7"
KB_URL = ("https://raw.githubusercontent.com/crypto2011/IDR/"
          + IDR_REVISION + "/kb%s.7z")
KB_ARTIFACTS = {
    "2": (1317716, "906643054f0cd8bd573e3483dbe0131c70ce4e2d"),
    "3": (1832208, "20ec3a2921af429e57784a8c170ad6a84fd6e627"),
    "4": (2565855, "7f6d0d0dff7dc078994b807735d334bfb22a186b"),
    "5": (3267247, "cb03982bf88fb3548222f7ccbb147fd1cdcfa4ee"),
    "6": (4805900, "c392d285de2caaac8ae2afa1833f1bfb4c5843e2"),
    "7": (5403530, "0b3b4f45844361ae5949db71482be1be7c0a69d2"),
    "2005": (6177636, "8a7afd942c2440c5f8d8379b0b85f360878f6ec3"),
    "2006": (6368767, "a0f7cbc55094c4ed15369244faa7f69a2995abc0"),
    "2007": (6929303, "9d5a0948a14f96c2a9b96b73b57aea9f36d92836"),
    "2009": (8005419, "8fc3853d05c291eb095787aa065507a70eec14aa"),
    "2010": (7537188, "e9519179d37736f958f9bf73686fb69e81e63a49"),
    "2011": (13059020, "675acf534f018135bb983005977023ca7aca8eb5"),
    "2012": (14166796, "2f144094d6bd7e2274a6c713941b1957ecb4c050"),
    "2013": (16478688, "50c9b17667ce0aca1d01f7ca03902d029d2b74ab"),
    "2014": (15120944, "29a367cfd15444244477260034099d4dde9de530"),
}


def source(tag):
    size, blob = KB_ARTIFACTS[tag]
    return {"repository": "crypto2011/IDR", "revision": IDR_REVISION,
            "path": "kb%s.7z" % tag, "size": size,
            "git_blob_sha1": blob}


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def fetch(tag, cache):
    archive = os.path.join(cache, "kb%s.7z" % tag)
    expected = source(tag)
    if not repro.verify_file(archive, expected):
        log("downloading kb%s" % tag)
    repro.fetch_verified(KB_URL % tag, archive, expected)
    target = os.path.join(cache, "kb%s-%s" %
                          (tag, expected["git_blob_sha1"][:12]))
    binfile = os.path.join(target, "kb%s.bin" % tag)
    stamp = os.path.join(target, "extract.json")
    extracted = repro.read_cache(stamp, expected)
    valid = (isinstance(extracted, dict)
             and repro.verify_file(binfile, extracted.get("binary", {})))
    if not valid:
        log("extracting kb%s" % tag)
        temporary = tempfile.mkdtemp(prefix=".kb%s." % tag, dir=cache)
        try:
            subprocess.run(["7z", "x", "-y", archive, "-o" + temporary],
                           check=True, capture_output=True)
            candidate = os.path.join(temporary, "kb%s.bin" % tag)
            if not os.path.exists(candidate):
                found = sorted(f for f in os.listdir(temporary)
                               if f.lower().endswith(".bin"))
                if len(found) != 1:
                    raise RuntimeError("expected exactly one .bin inside "
                                       "kb%s.7z" % tag)
                candidate = os.path.join(temporary, found[0])
                os.replace(candidate,
                           os.path.join(temporary, "kb%s.bin" % tag))
            candidate = os.path.join(temporary, "kb%s.bin" % tag)
            repro.write_cache(
                os.path.join(temporary, "extract.json"), expected,
                {"binary": {"size": os.path.getsize(candidate),
                            "sha256": repro.file_hash(candidate)}})
            if os.path.isdir(target):
                shutil.rmtree(target)
            os.replace(temporary, target)
        finally:
            if os.path.isdir(temporary):
                shutil.rmtree(temporary)
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
        t0 = time.time()
        try:
            binfile = fetch(tag, cache)
            build = generate.build_identity(binfile, source=source(tag))
            if repro.artifact_is_current(out, build):
                log("kb%s already built from current inputs, skipping" % tag)
                results.append((tag, "skipped", os.path.getsize(out), 0))
                continue
            work = os.path.join(workdir, "build%s" % tag)
            generate.generate(binfile, work, out, save_db=True, log=log,
                              source=source(tag))
            results.append((tag, "built", os.path.getsize(out), time.time() - t0))
        except Exception as exc:
            log("kb%s FAILED: %s" % (tag, exc))
            results.append((tag, "failed: %s" % exc, 0, time.time() - t0))

    print("\n%-8s %-10s %12s %8s" % ("version", "status", "bytes", "minutes"))
    for tag, status, size, secs in results:
        print("%-8s %-10s %12d %8.1f" % (tag, status[:10], size, secs / 60))
    log("total %.1f minutes" % ((time.time() - started) / 60))


if __name__ == "__main__":
    import binaryninja
    binaryninja.disable_default_log()
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "signatures"),
         sys.argv[2] if len(sys.argv) > 2 else "/tmp/delphi-warp-build",
         sys.argv[3].split(",") if len(sys.argv) > 3 else None)
