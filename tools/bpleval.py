#!/usr/bin/env python3
"""Check a package's own export names against an independently built library.

    python3 tools/bpleval.py <package.bpl> <library.warp> [--out JSON]

This is the measurement that says whether reading names out of a `.bpl` works
at all, and it is only possible for the releases IDR already covers.
`corpus/borlandrtl/vcl50.bpl` and `signatures/delphi-rtl-5.warp` describe the
same Delphi 5 runtime from two entirely unrelated inputs -- an export table the
linker wrote, and the `.dcu` files the compiler wrote by way of IDR's knowledge
base.  Every address where both have something to say is a test with ground
truth on both sides.

The comparison is by address rather than by GUID: the library is registered,
the package is analysed, and wherever WARP matches a function that the export
table also names, the two names must agree.  That tests the naming end to end,
including the `PACKAGEINFO` unit lookup, rather than testing a hash.

Two spellings are normalised before comparing, because they are the same name
written by two conventions rather than a disagreement:

* a compiler helper is `@GetMem` in a knowledge base and `__linkproc__ GetMem`
  in the mangling -- `bplkb` already rewrites the second into the first;
* unit case, because a knowledge base takes it from the `.dcu` filename and a
  package from `PACKAGEINFO`.

Run with a scratch Binary Ninja user directory so nothing else is registered:
only the library under test may supply a name.
"""

import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import bnenv                                       # noqa: E402
bnenv.scratch_user_directory()

import binaryninja as bn                                      # noqa: E402
from binaryninja import warp                                  # noqa: E402

from tools import bplkb                                       # noqa: E402


def compare(package, library):
    container = warp.WarpContainer.add("bpleval %s" % os.path.basename(library))
    container.add_source(library)

    claims = bplkb.readings(package)
    bv = bn.load(package, update_analysis=True,
                 options={"analysis.debugInfo.internal": False})
    bv.update_analysis_and_wait()

    rows = []
    for func in bv.functions:
        matched = warp.WarpFunction.get_matched(func)
        reading = claims.get(func.start)
        if matched and reading:
            rows.append((func.start, matched.name, reading.name))
    return bv, claims, rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package")
    parser.add_argument("library")
    parser.add_argument("--out", help="write every row to this JSON file")
    args = parser.parse_args(argv)

    bv, claims, rows = compare(args.package, args.library)
    agree = [r for r in rows if r[1].lower() == r[2].lower()]
    print("%s vs %s" % (os.path.basename(args.package),
                        os.path.basename(args.library)))
    print("  functions in the package        %d" % len(list(bv.functions)))
    print("  exports this pipeline names     %d" % len(claims))
    print("  of those, the library matches   %d" % len(rows))
    print("  identical name                  %d (%.2f%%)"
          % (len(agree), 100.0 * len(agree) / max(len(rows), 1)))

    differ = [r for r in rows if r not in agree]
    shape = collections.Counter()
    for _, matched, ours in differ:
        shape["same member, different owner"
              if matched.split("::")[-1].lower() == ours.split("::")[-1].lower()
              else "different member"] += 1
    for kind, count in shape.most_common():
        print("    %-34s %d" % (kind, count))
    for addr, matched, ours in differ[:20]:
        print("    %#x library=%s package=%s" % (addr, matched, ours))
    if args.out:
        json.dump(rows, open(args.out, "w"))
    return 0


if __name__ == "__main__":
    bn.disable_default_log()
    sys.exit(main())
