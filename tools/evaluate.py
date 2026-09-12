#!/usr/bin/env python3
"""Measure a signature library against the corpus.

Recall is easy to measure and easy to be pleased by; precision is the number
that matters for a library other people will load.  There is one source of
independent ground truth available: the delphi_rtti plugin recovers names from
the metadata inside each binary, with no reference to any signature library.
Where both name the same function they must agree, and every disagreement is a
real defect in one of them.

Also reports match rate against binary size, because WARP masks a constant as
an address when it lands inside the mapped image -- so the same function can
hash differently in a small executable than in a large one, and a library
implicitly targets a size range.

    python3 tools/evaluate.py <corpus_dir> [limit] [start]

Run from the repository root, or with the repository's parent directory on
`sys.path`: this one *does* want the plugin's decoder, unlike the build tools.

The command is a validation check by default: processing errors, empty input,
zero RTTI/WARP overlap, or precision below ``--min-precision`` return nonzero.
Use ``--report-only`` for an exploratory report whose exit status is always
successful, or ``--allow-empty`` when an empty selection is intentional.
"""

import argparse
import os
import sys

# Both the checkout (for ``tools``) and its parent (for ``delphinja``).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(_ROOT))
sys.path.insert(0, _ROOT)

from tools import evalutil                                      # noqa: E402


def _load_view(path):
    import binaryninja as bn
    return bn.load(path, update_analysis=True,
                   options={"analysis.debugInfo.internal": False})


def _warp_match(func):
    from binaryninja import warp
    return warp.WarpFunction.get_matched(func)


def _disable_logs():
    import binaryninja as bn
    bn.disable_default_log()


def _configure():
    evalutil.configure_binary_ninja("delphinja-evaluate-")
    _disable_logs()


def class_of(name):
    """The class component of an RTTI `Class.Member` name.

    A generic instantiation writes its type arguments out in full, dots and
    all -- `TList<System.Classes.TComponent>.Add` -- so the member boundary is
    the last dot *outside* the angle brackets, not the first dot in the
    string. Cutting at the first one yields `TList<System`, which can match
    nothing, and scored every generic as a disagreement.
    """
    depth = 0
    cut = -1
    for i, ch in enumerate(name):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == "." and depth == 0:
            cut = i
    return name if cut < 0 else name[:cut]


def evaluate(path):
    from delphinja.rtti import apply as A
    out = {"file": os.path.basename(path), "size": os.path.getsize(path)}
    bv = _load_view(path)
    if bv is None:
        raise RuntimeError("Binary Ninja could not open %s" % path)
    try:
        bv.update_analysis_and_wait()
        funcs = list(bv.functions)
        warped = {f.start: _warp_match(f) for f in funcs}
        warped = {a: w for a, w in warped.items() if w}
        out["functions"] = len(funcs)
        out["matched"] = len(warped)

        # Independent ground truth from the binary's own metadata.
        md = A.DelphiMetadata(bv).scan()
        if not md.vmts:
            out["rtti"] = 0
            return out
        claims = {}
        for vmt in md.vmts.values():
            for m in vmt.methods + vmt.methods_ex:
                claims[m["addr"]] = "%s.%s" % (vmt.name, m["name"])
            for d in vmt.dynamic:
                claims[d["addr"]] = vmt.name
        out["rtti"] = len(claims)

        both = set(claims) & set(warped)
        agree = 0
        disagree = []
        for addr in both:
            rtti = claims[addr]
            wname = warped[addr].name
            # RTTI knows Class.Member; WARP knows Unit::Class::Member. Compare
            # the class component, which is the part both can see.
            cls = class_of(rtti)
            if cls and (("::%s::" % cls) in wname or
                        wname.endswith("::" + cls)):
                agree += 1
            else:
                disagree.append((hex(addr), rtti, wname))
        out["overlap"] = len(both)
        out["agree"] = agree
        out["disagree"] = disagree[:5]
        return out
    finally:
        bv.file.close()


def main(argv=None, configure=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    parser.add_argument("limit", nargs="?", type=int)
    parser.add_argument("start", nargs="?", type=int, default=0)
    parser.add_argument("--min-precision", type=evalutil.percentage,
                        default=100.0,
                        help="minimum agreement on RTTI/WARP overlap (default: 100)")
    parser.add_argument("--allow-empty", action="store_true",
                        help="allow an empty corpus or zero RTTI/WARP overlap")
    parser.add_argument("--report-only", action="store_true",
                        help="print failures but return success")
    args = parser.parse_args(argv)
    if configure:
        _configure()

    files = []
    for root, _, names in os.walk(args.corpus):
        for n in names:
            if n.lower().endswith(".exe"):
                files.append(os.path.join(root, n))
    files.sort()
    files = (files[args.start:args.start + args.limit]
             if args.limit is not None else files[args.start:])
    print("%-34s %8s %7s %7s %6s %6s %6s" %
          ("file", "size", "funcs", "matched", "rate", "overlap", "agree"))
    tot_o = tot_a = processed = errors = 0
    for p in files:
        try:
            r = evaluate(p)
        except Exception as exc:
            print("%-34s  ERROR %s" % (os.path.basename(p)[:34], exc))
            errors += 1
            continue
        processed += 1
        rate = 100.0 * r["matched"] / max(r["functions"], 1)
        print("%-34s %8d %7d %7d %5.0f%% %6s %6s" %
              (r["file"][:34], r["size"], r["functions"], r["matched"], rate,
               r.get("overlap", "-"), r.get("agree", "-")))
        for d in r.get("disagree", []):
            print("      DISAGREE %s rtti=%s warp=%s" % d)
        tot_o += r.get("overlap", 0)
        tot_a += r.get("agree", 0)
    if tot_o:
        print("\nprecision on overlapping names: %d/%d = %.1f%%"
              % (tot_a, tot_o, 100.0 * tot_a / tot_o))
    problems = evalutil.validation_problems(
        processed, errors, tot_a, tot_o, args.min_precision, args.allow_empty)
    for problem in problems:
        print("VALIDATION FAILED: %s" % problem)
    return evalutil.exit_status(problems, args.report_only)


if __name__ == "__main__":
    raise SystemExit(main(configure=True))
