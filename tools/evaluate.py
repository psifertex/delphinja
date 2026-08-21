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

    python3 tools/evaluate.py <corpus_dir> [limit]

Run from the repository root, or with the repository's parent directory on
`sys.path`: this one *does* want the plugin's decoder, unlike the build tools.
"""

import os
import sys

import binaryninja as bn
from binaryninja import warp

# The repository's parent, so `delphinja.rtti` imports the decoder from this
# checkout rather than from whatever happens to be installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))


def evaluate(path):
    from delphinja.rtti import apply as A
    out = {"file": os.path.basename(path), "size": os.path.getsize(path)}
    bv = bn.load(path, update_analysis=True,
                 options={"analysis.debugInfo.internal": False})
    bv.update_analysis_and_wait()
    funcs = list(bv.functions)
    warped = {f.start: warp.WarpFunction.get_matched(f) for f in funcs}
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
        for m in vmt.methods:
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
        # RTTI knows Class.Member; WARP knows Unit::Class::Member. Compare the
        # class component, which is the part both can see.
        cls = rtti.split(".")[0]
        # Precedence matters here: without the parentheses this reads as
        # (cls and A) or B and the endswith test fires for every name.
        if cls and (("::%s::" % cls) in wname or wname.endswith("::" + cls)):
            agree += 1
        else:
            disagree.append((hex(addr), rtti, wname))
    out["overlap"] = len(both)
    out["agree"] = agree
    out["disagree"] = disagree[:5]
    return out


def main(corpus, limit=None, start=0):
    files = []
    for root, _, names in os.walk(corpus):
        for n in names:
            if n.lower().endswith(".exe"):
                files.append(os.path.join(root, n))
    files.sort()
    files = files[start:start + limit] if limit else files[start:]
    print("%-34s %8s %7s %7s %6s %6s %6s" %
          ("file", "size", "funcs", "matched", "rate", "overlap", "agree"))
    tot_o = tot_a = 0
    for p in files:
        try:
            r = evaluate(p)
        except Exception as exc:
            print("%-34s  ERROR %s" % (os.path.basename(p)[:34], exc))
            continue
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


if __name__ == "__main__":
    bn.disable_default_log()
    main(sys.argv[1],
         int(sys.argv[2]) if len(sys.argv) > 2 else None,
         int(sys.argv[3]) if len(sys.argv) > 3 else 0)
