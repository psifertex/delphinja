#!/usr/bin/env python3
"""Build the post-XE6 signature library from the corpus's own extended RTTI.

    python3 tools/build_rtti.py [workdir] [--out FILE] [--votes N]
                                [--hold-out SUBSTRING ...] [--corpus DIR]

Three phases, and only the first is expensive:

1. **Harvest** every corpus binary whose RTTI names namespaced RTL units --
   the XE2-and-later form -- caching one JSON per binary in `workdir`, so a
   re-run with different consensus rules costs seconds.
2. **Consensus** across those readings (`tools/rttikb.py`).
3. **Generate** a `.warp` from a covering subset of the harvested binaries.

`--hold-out` names binaries to exclude from the *build* while still harvesting
them, which is how precision is measured: evaluate the resulting library on a
binary that contributed nothing to it and compare its names against that
binary's own metadata, which `tools/evaluate.py` already does.

Run from the repository root.  Like the other build entry points this imports
`tools.<module>` rather than the `delphinja` package, so the plugin's workflow
is not registered into the build process -- with one exception, `rttigen`,
which imports the decoder deliberately and says so.
"""

import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import bnenv                                        # noqa: E402
bnenv.scratch_user_directory()

from tools import rttikb                                       # noqa: E402
from tools import rttigen                                      # noqa: E402
from tools.rttigen import log                                  # noqa: E402

# The compiler stamps this into binaries built by XE2 and later, and the
# CompilerVersion it names is the one thing a Delphi binary says exactly.  It
# is absent often enough (installers, IDE-stripped builds) that it cannot be
# the selection rule, so it is read for the report only.
COMPILER = re.compile(
    rb"(?:Embarcadero|CodeGear|Borland) Delphi for Win32 compiler version "
    rb"(\d+\.\d+)")

# The tag `library()` and `DELPHI_ERAS` know this library by.  Not a release
# name: the readings come from every namespaced-RTL binary in the corpus, which
# is XE2 (2011) onwards, and the consensus keeps whatever holds across them.
TAG = "xe2plus"

SIGNATURES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "signatures")
DEFAULT_OUT = os.path.join(SIGNATURES, "delphi-rtl-%s.warp" % TAG)


def compiler_version(path):
    match = COMPILER.search(open(path, "rb").read())
    return match.group(1).decode() if match else None


def candidates(corpus):
    """The corpus files worth analysing, selected by content, not by version.

    What a binary has to have is an RTL class whose unit name is *namespaced* --
    the XE2-and-later form that `rttikb.is_rtl` recognises -- and the unit name
    is a literal string in the RTTI, so grepping for one is an exact test that
    costs a read instead of a minute of analysis.  Four of the units are looked
    for rather than one because a small program need not link `System.Rtti` or
    `System.Classes`, but everything links `System.SysUtils`.

    Measured on the 117-file corpus: 32 files pass, 85 are skipped, and
    building from the 32 rather than from every file that carries any RTTI at
    all changes the consensus by one reading -- the pre-XE2 binaries name their
    units `Classes` and `SysUtils`, which `is_rtl` does not accept and cannot,
    since an application is free to have a unit called `Classes`.
    """
    marker = re.compile(rb"\bSystem\.(SysUtils|Classes|TypInfo|Rtti)\b")
    out = []
    for root, _, names in os.walk(corpus):
        for name in names:
            if not name.lower().endswith((".exe", ".dll", ".bpl")):
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as handle:
                if marker.search(handle.read()):
                    out.append(path)
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workdir", nargs="?", default="/tmp/delphi-rtti-build")
    ap.add_argument("--corpus", default="corpus")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--votes", type=int, default=3,
                    help="independent projects that must agree on a reading")
    ap.add_argument("--blocks", type=int, default=2,
                    help="smallest body, in basic blocks, worth a signature")
    ap.add_argument("--views", type=int, default=12,
                    help="most binaries to hold open while generating")
    ap.add_argument("--hold-out", action="append", default=[],
                    help="harvest but do not build from binaries matching this")
    ap.add_argument("--only-harvest", action="store_true")
    args = ap.parse_args()

    paths = candidates(args.corpus)
    log("%d corpus files" % len(paths))
    records = rttigen.harvest_corpus(paths, os.path.join(args.workdir, "kb"))
    useful = [r for r in records if r["entries"]]
    log("%d files carry RTTI-named functions" % len(useful))
    if args.only_harvest:
        return

    held = [r for r in useful
            if any(h in r["file"] for h in args.hold_out)]
    build_from = [r for r in useful if r not in held]
    if held:
        log("held out of the build: %s"
              % ", ".join(os.path.basename(r["file"]) for r in held))

    # Every already-published Delphi library, not just this era's: with no
    # layout to go on `signatures.delphi_tags` registers all of them, so any of
    # them can be loaded beside this one.
    shipped = rttigen.shipped_guids(
        sorted(p for p in glob.glob(os.path.join(SIGNATURES, "delphi-rtl-*.warp"))
               if os.path.abspath(p) != os.path.abspath(args.out)))
    log("%d GUIDs already claimed by the shipped libraries" % len(shipped))

    consensus = rttikb.Consensus(args.votes, args.blocks)
    for record in build_from:
        consensus.add(record)
    report = consensus.report(shipped)
    for key, value in report.items():
        log("  %-18s %d" % (key, value))

    keep = consensus.keep(shipped)
    if not keep:
        raise SystemExit("no reading survived the consensus")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    _, totals = rttigen.generate(keep, args.out, args.views)
    json.dump({"report": report, "totals": totals,
               "versions": {os.path.basename(r["file"]):
                            compiler_version(r["file"]) for r in useful}},
              open(os.path.join(args.workdir, "build.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
