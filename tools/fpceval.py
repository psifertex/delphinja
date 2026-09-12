#!/usr/bin/env python3
"""Measure an FPC signature library against the corpus.

    python3 tools/fpceval.py <corpus_dir> [--libs a.warp,b.warp]
                             [--ref <unit dir>] [--limit N] [--filter TEXT]

Recall is the easy number and the misleading one.  The Delphi evaluator gets
independent ground truth from the RTTI the compiler bakes into every binary;
FPC emits no such thing, so precision has to come from somewhere else.

It comes from the reference objects themselves.  A signature claims that the
bytes at some address are a particular RTL routine, and the shipped `.o` holds
exactly the bytes the linker copied in -- so the claim is checkable: read the
function back out of the target binary and compare it byte for byte with the
reference, ignoring the offsets the relocation table says the linker rewrote.

What that proves: the matched name belongs to bytes identical to the reference
routine's, so the match is not a collision between two different routines.

What it does not prove: that the *name* is right.  The name comes from the
demangler, and if that mis-parses a symbol the check still passes -- it
compares code, not names.  Nor does it say anything about the functions that
should have matched and did not; a byte-level check can only score the claims
that were made.  A "verified" rate near 100% therefore means "the matcher is
not confusing routines", not "the library is correct".

Processing errors and empty input fail the command. With ``--ref``, zero
checkable matches or a rate below ``--min-verified`` fail too. Use
``--report-only`` for exploratory measurement and ``--allow-empty`` for an
intentionally empty selection.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    evalutil.configure_binary_ninja("delphinja-fpceval-")
    _disable_logs()


def reference_index(roots, log=print):
    """Qualified name -> [(code bytes, relocated byte offsets)].

    Overloads share a qualified name (the parameter types that distinguish
    them are dropped by `Unit::Class::Member`), so each name keeps a list and
    a match counts as verified if it agrees with any of them.
    """
    from tools import fpcgen, fpcname, fpcstage
    paths = fpcgen.object_files(roots)
    oracle = fpcgen.case_oracle(paths, log)
    layout = fpcstage.Layout(paths, log=log)
    index = {}
    for _addr, p in layout.procs:
        name = fpcname.demangle(p["name"], p["unit"]).qualified(oracle)
        index.setdefault(name, []).append((p["code"], p["holes"]))
    log("reference: %d distinct names from %d routines"
        % (len(index), len(layout.procs)))
    return index, layout


def _same(binary_bytes, reference, holes):
    """Equal outside the bytes the object's relocation table marks.

    `holes` comes from the reference object itself, so this is exact rather
    than a tolerance: every byte the linker was entitled to rewrite is
    excluded, and every other byte must agree.
    """
    if len(binary_bytes) != len(reference):
        return False
    if binary_bytes == reference:
        return True
    for i, (a, b) in enumerate(zip(binary_bytes, reference)):
        if a != b and i not in holes:
            return False
    return True


def register(libs):
    from binaryninja import warp
    for path in libs:
        container = warp.WarpContainer.add(
            "fpceval %s" % os.path.basename(path))
        container.add_source(os.path.abspath(path))


def evaluate(path, index=None):
    out = {"file": os.path.basename(path), "size": os.path.getsize(path)}
    bv = _load_view(path)
    if bv is None:
        raise RuntimeError("Binary Ninja could not open %s" % path)
    try:
        bv.update_analysis_and_wait()
        funcs = list(bv.functions)
        matched = {}
        for f in funcs:
            w = _warp_match(f)
            if w:
                matched[f.start] = (w.name, f)
        out["functions"] = len(funcs)
        out["matched"] = len(matched)
        if index is None:
            return out

        checked = verified = 0
        wrong = []
        for addr, (name, func) in matched.items():
            refs = index.get(name)
            if not refs:
                continue
            checked += 1
            size = max(r.end for r in func.address_ranges) - func.start
            ok = False
            for code, holes in refs:
                try:
                    got = bv.read(addr, len(code))
                except Exception:
                    break
                if _same(got, code, holes):
                    ok = True
                    break
            if ok:
                verified += 1
            elif len(wrong) < 5:
                wrong.append((hex(addr), name, size))
        out["checked"] = checked
        out["verified"] = verified
        out["wrong"] = wrong
        return out
    finally:
        bv.file.close()


def main(argv=None, configure=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    parser.add_argument("--libs", help="comma-separated WARP libraries")
    parser.add_argument("--ref", help="comma-separated reference object roots")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--filter")
    parser.add_argument("--min-verified", type=evalutil.percentage,
                        default=100.0,
                        help="minimum byte verification rate (default: 100)")
    parser.add_argument("--allow-empty", action="store_true",
                        help="allow an empty corpus or zero checkable matches")
    parser.add_argument("--report-only", action="store_true",
                        help="print failures but return success")
    args = parser.parse_args(argv)
    if configure:
        _configure()
    corpus = args.corpus
    libs = args.libs.split(",") if args.libs else []
    refs = args.ref.split(",") if args.ref else []

    if libs:
        register(libs)
        print("registered %d librar%s" % (len(libs),
                                          "y" if len(libs) == 1 else "ies"))
    index = None
    if refs:
        index, _ = reference_index(refs)

    files = []
    for root, _dirs, names in os.walk(corpus):
        for n in names:
            if n.lower().endswith(".exe"):
                files.append(os.path.join(root, n))
    files.sort()
    if args.filter:
        files = [f for f in files if args.filter in f]
    if args.limit is not None:
        files = files[:args.limit]

    print("%-36s %9s %7s %7s %6s %7s %8s"
          % ("file", "size", "funcs", "matched", "rate", "checked", "verified"))
    tot_f = tot_m = tot_c = tot_v = processed = errors = 0
    for p in files:
        try:
            r = evaluate(p, index)
        except Exception as exc:                            # noqa: BLE001
            print("%-36s  ERROR %s" % (os.path.basename(p)[:36], exc))
            errors += 1
            continue
        processed += 1
        rate = 100.0 * r["matched"] / max(r["functions"], 1)
        print("%-36s %9d %7d %7d %5.1f%% %7s %8s"
              % (os.path.relpath(p, corpus)[:36], r["size"], r["functions"],
                 r["matched"], rate, r.get("checked", "-"),
                 r.get("verified", "-")))
        for w in r.get("wrong", []):
            print("      UNVERIFIED %s %s size=%d" % w)
        tot_f += r["functions"]
        tot_m += r["matched"]
        tot_c += r.get("checked", 0)
        tot_v += r.get("verified", 0)
    print("\ntotal: %d functions, %d matched (%.1f%%)"
          % (tot_f, tot_m, 100.0 * tot_m / max(tot_f, 1)))
    if tot_c:
        print("byte-verified: %d/%d = %.1f%% of checkable matches"
              % (tot_v, tot_c, 100.0 * tot_v / tot_c))
    problems = evalutil.validation_problems(
        processed, errors,
        tot_v if index is not None else None,
        tot_c if index is not None else None,
        args.min_verified, args.allow_empty)
    for problem in problems:
        print("VALIDATION FAILED: %s" % problem)
    return evalutil.exit_status(problems, args.report_only)


if __name__ == "__main__":
    raise SystemExit(main(configure=True))
