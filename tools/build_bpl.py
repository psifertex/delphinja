#!/usr/bin/env python3
"""Build one `delphi-rtl-<tag>.warp` from a release's runtime packages.

    python3 tools/build_bpl.py <tag> <package.bpl> [more.bpl ...]
                               [--out DIR] [--no-exclude-shipped]
                               [--no-prototypes]

Every package given goes into one library, because they are one RTL split over
several files -- `rtl270.bpl` holds `System.*` and `Winapi.*`, `vcl270.bpl`
holds `Vcl.*`, and a body that appears in both has to be recognised as one
body rather than two.

By default the build excludes every function GUID an already-shipped library
claims, for the reason [RTTI.md](RTTI.md) sets out: libraries are selected by
VMT era, Delphi has not changed the standard virtual count since 2009, and two
loaded libraries claiming one GUID under two names is an ambiguity the matcher
resolves by declining a match the older library was already making.
`--no-exclude-shipped` turns that off, which is only useful for measuring how
large the overlap is.

Run from the repository root.  Like every other build entry point this points
BN_USER_DIRECTORY at a scratch directory before importing binaryninja, so an
unattended run cannot disturb the user's configuration.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import bnenv                                       # noqa: E402
bnenv.scratch_user_directory()

from tools import bplgen                                      # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGNATURES = os.path.join(ROOT, "signatures")


def shipped(outfile):
    """Every library already in `signatures/`, except the one being written."""
    if not os.path.isdir(SIGNATURES):
        return []
    return sorted(os.path.join(SIGNATURES, f)
                  for f in os.listdir(SIGNATURES)
                  if f.startswith("delphi-rtl-") and f.endswith(".warp")
                  and os.path.join(SIGNATURES, f) != outfile)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="library tag, e.g. 10.4")
    parser.add_argument("packages", nargs="+", help=".bpl files")
    parser.add_argument("--out", default=SIGNATURES)
    parser.add_argument("--no-exclude-shipped", action="store_true")
    parser.add_argument("--no-prototypes", action="store_true")
    args = parser.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    outfile = os.path.join(args.out, "delphi-rtl-%s.warp" % args.tag)
    bplgen.generate(args.packages, outfile,
                    shipped=() if args.no_exclude_shipped else shipped(outfile),
                    prototypes=not args.no_prototypes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
