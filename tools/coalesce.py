#!/usr/bin/env python3
"""Coalesce the shipped Delphi libraries into a per-era core plus deltas.

Every other module in `tools/` builds a library from an outside source -- an
IDR knowledge base, an object file, a binary's own metadata, a runtime
package.  This one builds no signatures at all.  Its input is the seventeen
per-release `delphi-rtl-*.warp` files the others produce, and its output is the
same signatures rearranged so that no two libraries loaded together claim the
same function GUID under different names.

## Why rearranging is worth a tool

The seventeen libraries were built independently and never compared, so a
routine that did not change between Delphi 4 and Delphi 2007 is signed seven
times.  Measured across the shipped set: 466,657 (library, GUID) claims over
236,186 distinct GUIDs -- 49.4% of what ships is a duplicate of something else
that ships.

That would be merely wasteful if the matcher ignored it.  It does not.  Binary
Ninja enumerates WARP containers in a fresh random order every process start,
and when two *containers* claim one GUID the first-enumerated one wins, so the
name a function gets changes from run to run.  Two claimants in the *same*
container behave differently again: the ambiguity is noticed, and the matcher
declines rather than guessing.  Both behaviours are documented, with a
minimal reproduction, in the report this tool was written to answer.

The consequence for a library publisher is a rule with two halves:

* **duplicate claims under identical names are harmless**, in one container or
  in several;
* **duplicate claims under different names are poison**, silently nondetermin-
  istic across containers and silently declined within one.

So the fix is not to make duplicates agree -- there is no API that renames a
signature after the fact, short of rebuilding it from an analysed image -- but
to make sure a GUID is claimed **once** inside any set of libraries that load
together.

## What loads together

`integration/signatures.py` selects libraries by VMT era, and that selection is
what bounds the problem.  There are four groups, and only two of them hold more
than one library:

| era | virtual slots | libraries |
| --- | --- | --- |
| `2`    | 4  | `2` |
| `3`    | 5  | `3` |
| `8`    | 8  | `4`, `5`, `6`, `7`, `2005`, `2006`, `2007` |
| `11`   | 11 | `2009`, `2010`, `2011`, `2012`, `2013`, `2014`, `xe2plus`, `10.4` |

A GUID shared between `5` and `2013` costs nothing at match time, because no
binary ever loads both.  A GUID shared between `5` and `2007` costs a name.

## The shape of the output

Per era group:

* `delphi-rtl-core-<era>.warp` holds every GUID that more than one library in
  the group claims, once, under one name.
* `delphi-rtl-<tag>-only.warp` holds what remains to that library alone.

The two are disjoint by construction, and the deltas are disjoint from each
other, so an era's containers cannot produce a duplicate claim between them.
Eras `2` and `3` hold one library each and get a delta with no core.

One GUID, one library -- but not one entry.  Two things put several entries on
one GUID, and both are deliberate:

* a folded GUID that `FOLDED_POLICY` keeps contributes one entry per routine in
  the fold, so the matcher chooses between them from its constraints the way it
  does today -- inside one container rather than across several, which is the
  part that was nondeterministic;
* a name several of the era's libraries agree on is kept **once per library**,
  because an entry carries the constraints of the release it was built from and
  those are what the matcher tests.  See `plan` for what keeping only one costs.

Neither puts two *names* on one GUID across two files, which is the thing that
races.

## Which name a shared GUID keeps

This is the only judgement in the tool, and a wrong one mis-names a function
everywhere.  Claims are compared after normalising away the two things that
demonstrably vary between eras without changing the routine:

* the unit's **namespace prefix** -- `Buttons` became `Vcl.Buttons` at XE2, and
  the shipped libraries follow their own `.dcu` naming;
* **letter case** -- IDR's older knowledge bases record `SYSUTILS`, the middle
  ones `sysutils`, the newer ones `SysUtils`.

If every claim agrees under that normalisation, the GUID is kept and the
surviving spelling is chosen by vote: the most-claimed spelling wins, ties
going to the newest library, because a spelling that more libraries agree on
is the one more binaries were built against.  If the claims still disagree the
GUID is **dropped from the era entirely**, which is the same call `rttigen`
and `bplgen` already make when a second name claims a GUID: two names on one
body is evidence against both rather than for either.

Then there is the case a name vote cannot reach: **a GUID more than one name
claims inside a single library**, the linker having folded several routines
onto one body.  22,158 of those ship today.  What to do with them is not a
judgement but a measurement, it comes out differently per era, and
`FOLDED_POLICY` carries both the answer and the numbers behind it.

One further drop, in the same spirit as the disagreement rule:

* **placeholder names, but only as votes.**  IDR's Delphi 3 knowledge base
  names unresolved procedures `unit::_NF__1A2`.  A placeholder is no evidence
  of *which* routine this is, so it never outvotes a real name -- but where it
  is the only name on offer it is kept, because it still names the unit and
  nothing is ambiguous about a GUID one library claims.
* nothing else.  A GUID only one library claims is copied through untouched,
  name, prototype and constraints included.

## Usage

    mkdir per-release && for t in 2 3 4 5 6 7 2005 2006 2007 2009 2010 \
        2011 2012 2013 2014 xe2plus 10.4; do
      git show <commit>:signatures/delphi-rtl-$t.warp > per-release/delphi-rtl-$t.warp
    done
    BN_USER_DIRECTORY=... bnpython3 tools/coalesce.py <outdir> per-release
    BN_USER_DIRECTORY=... bnpython3 tools/coalesce.py <outdir> --compress
    BN_USER_DIRECTORY=... bnpython3 tools/coalesce.py <outdir> --verify

The per-release libraries are the input, and `signatures/` no longer holds
them -- this tool superseded them and they were deleted -- so a rebuild starts
by getting them back out of git.  The first pass selects and stages into
`<outdir>/raw` and writes a `plan.tsv` recording every decision; the second
rewrites them compressed into `<outdir>` itself.  They are separate runs
because the second must not share a process with the containers the first
registers.  `--verify` reads the result back and checks it against `plan.tsv`.
Nothing is written outside `<outdir>`.
"""

import collections
import os
import re
import shutil
import sys

if __package__:
    from . import repro
else:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools import repro

#: The library sets `integration.signatures.DELPHI_ERAS` loads together, named
#: by the era rather than by the VMT slot count so the output file names read.
ERAS = collections.OrderedDict([
    ("2", ["2"]),
    ("3", ["3"]),
    ("8", ["4", "5", "6", "7", "2005", "2006", "2007"]),
    ("11", ["2009", "2010", "2011", "2012", "2013", "2014",
            "xe2plus", "10.4"]),
])

#: Oldest first.  Used only to break a tie in the spelling vote, where the
#: newest library wins: a tie means the same number of releases spelled it each
#: way, and the later spelling is the one a reader is more likely to recognise.
AGE = ["2", "3", "4", "5", "6", "7", "2005", "2006", "2007", "2009", "2010",
       "2011", "2012", "2013", "2014", "xe2plus", "10.4"]

#: IDR writes this for a procedure its knowledge base could not name.  It
#: carries no information beyond the unit, so it never wins a vote and never
#: keeps a GUID alive on its own.
PLACEHOLDER = re.compile(r"::_NF__[0-9A-Fa-f]+$")

#: What to do, per era, with a GUID more than one name claims inside a single
#: library -- the linker having folded several routines onto one body.
#:
#: This is a measurement, not a preference.  A folded GUID reaches the matcher
#: as several candidate names, and the matcher chooses between them using the
#: constraints stored beside each one -- the GUIDs of the functions it calls.
#: How well that choice goes is an empirical question, and the answer differs
#: sharply by era.  Scoring only the folded-GUID matches of a run against the
#: binary's own RTTI:
#:
#:   era 3   Compil32.exe (D3.02)          33 / 34    97%
#:   era 8   Demo.exe (D5)                 39 / 45    87%
#:   era 8   Launcher.exe (D7)             40 / 47    85%
#:   era 11  ImageWriterSvc.exe (D12)      60 / 187   32%
#:
#: against 96-99% for unfolded GUIDs in the same runs.  So for the older eras
#: the constraints do the job and dropping the fold throws away a name that was
#: usually right; for the Unicode era they do not, and two thirds of what a
#: folded GUID contributes is wrong.  Hence keep below eleven slots, drop at
#: and above.
#:
#: The alternative to trusting the matcher is to pick one of the folded names
#: here.  Two rules were tried and both are far worse than leaving the choice
#: to the constraints, on era 8 specifically:
#:
#:   plurality over the era's libraries   2 / 11 and 4 / 13 right
#:   defer to a library that did not fold 2 / 8 and 6 / 9 right
#:
#: -- so the fold is kept whole rather than collapsed.  What coalescing removes
#: is only the *spelling* duplicates within it, which is what made the choice
#: nondeterministic: the seven era-8 libraries offer `SYSTEM::TObject::Destroy`
#: and `System::TObject::Destroy` from seven containers, and which one answers
#: depends on container enumeration order.  One library, one spelling each,
#: same candidates.
FOLDED_POLICY = {"2": "keep", "3": "keep", "8": "keep", "11": "drop"}


def unit_of(name):
    """The unit component of a `Unit::Class::Member` signature name."""
    return name.split("::", 1)[0]


def member_of(name):
    """Everything after the unit, or "" for a bare unit name."""
    parts = name.split("::", 1)
    return parts[1] if len(parts) > 1 else ""


def normalise(name):
    """The comparison key: same routine, whatever era spelled it.

    Drops the unit's namespace prefix (`Vcl.Buttons` -> `buttons`) and folds
    case.  Both vary across the shipped libraries for reasons that have
    nothing to do with the code -- XE2 renamed the units, and IDR's knowledge
    bases record the `.dcu` name in whatever case that release used.  What is
    left is the unit's own name and the member path, which is what actually
    identifies the routine.
    """
    return "%s::%s" % (unit_of(name).split(".")[-1].lower(),
                       member_of(name).lower())


def vote(claims):
    """The winning spelling among `{tag: name}`, or None if they disagree.

    A claim whose name is a placeholder is not a vote; it is removed first and
    only counts to the extent that it does not veto the real names.  If every
    remaining claim normalises to the same routine, the most-claimed spelling
    wins and the newest library breaks a tie.
    """
    real = {t: n for t, n in claims.items() if not PLACEHOLDER.search(n)}
    # A GUID *every* library names with a placeholder has no better name to be
    # had, and dropping it would lose the unit, which is real information.  So
    # the placeholders vote among themselves; being per-knowledge-base
    # numbering they rarely agree, and where they do not the GUID goes.
    real = real or claims
    if len({normalise(n) for n in real.values()}) > 1:
        return None
    tally = collections.Counter(real.values())
    best = max(tally, key=lambda n: (tally[n],
                                     max(AGE.index(t) for t, m in real.items()
                                         if m == n)))
    return best


def routines(here):
    """`{normalised name: {tag: spelling}}` for one GUID's claims in one era.

    A GUID the linker folded is several routines sharing a body, and this is
    the set of them -- with the era's spelling variants of each collapsed
    together, so `SYSTEM::TObject::Destroy` and `System::TObject::Destroy`
    are one routine with two spellings rather than two candidates.
    """
    groups = collections.defaultdict(dict)
    for tag, names in here.items():
        for name in names:
            groups[normalise(name)][tag] = name
    return groups


def spellings_of(group, keep_all):
    """`[(name, [library, ...]), ...]` for one routine's claims in one era.

    The libraries that claim one routine do not always spell it the same way,
    and only one spelling can survive without putting two names on one GUID.
    `keep_all` is the experiment that says otherwise: keep every spelling, each
    with the libraries that used it, so that no library's constraints are lost
    to a spelling it did not win.  It is off because it costs more than it
    buys -- see COALESCE.md.
    """
    if not keep_all:
        name = vote(group)
        return [(name, sorted((t for t, m in group.items() if m == name),
                              key=AGE.index))]
    by_spelling = collections.defaultdict(list)
    for tag, name in group.items():
        by_spelling[name].append(tag)
    return [(n, sorted(ts, key=AGE.index))
            for n, ts in sorted(by_spelling.items())]


def plan(claims, folded_policy=None, keep_all_spellings=False):
    """Decide, per era, what every GUID becomes.

    `claims` is `{guid: {tag: {name, ...}}}` -- a name *set* per library,
    because a shipped library can hold several entries for one GUID.

    Returns `(assignments, stats)`.  An assignment is
    `(era, guid, destination_tag, name, sources)`; `destination_tag` is
    `"core-<era>"` for a GUID more than one library claims and `"<tag>-only"`
    for one only `tag` claims, and `sources` is every library of the era that
    claims that GUID under exactly that name.  A GUID that appears in several
    eras gets an assignment in each, independently: the eras never load
    together, so they are allowed to disagree, and each keeps the spelling its
    own libraries voted for.

    `sources` is a list rather than the single library the spelling vote
    happened to come from because **an entry carries the constraints of the
    release it was built from** -- the GUIDs of the functions that body calls.
    Those are what the matcher tests when it has to choose, and they are
    release-specific even where the body is not.  Measured on a Delphi 5
    binary, splitting the matches it used to make by which library the one
    surviving entry had been copied from:

        copied from delphi-rtl-5      64 / 67 still match   96%
        copied from delphi-rtl-7      11 / 26               42%
        copied from delphi-rtl-2007  155 / 297              52%

    So keeping one entry per GUID silently narrows the library to whichever
    release the spelling vote favoured, and costs roughly half the matches on
    every other release in the era.  Keeping one entry per *library* costs
    space and nothing else: every one of them carries the same GUID and the
    same name, and a duplicate claim under an identical name is the case the
    matcher handles without ambiguity.  Libraries that spell the name
    differently are still dropped -- their entry cannot be kept without
    putting two spellings of one routine in one file, which is the race this
    whole tool exists to remove.

    A folded GUID gets one assignment per routine in the fold, all to the same
    destination -- see `FOLDED_POLICY` for when that happens instead of a drop.
    Every other GUID gets exactly one.
    """
    policy = FOLDED_POLICY if folded_policy is None else folded_policy
    assignments = []
    stats = collections.defaultdict(collections.Counter)
    for era, tags in ERAS.items():
        counts = stats[era]
        present = set(tags)
        for guid, by_tag in claims.items():
            here = {t: n for t, n in by_tag.items() if t in present}
            if not here:
                continue
            counts["guids"] += 1
            counts["claims"] += len(here)
            if any(len(n) > 1 for n in here.values()):
                counts["folded"] += 1
                if policy.get(era, "drop") == "drop":
                    counts["dropped folded"] += 1
                    continue
                # Kept: every routine in the fold, each spelled once, all in
                # the one library so the choice between them is made inside a
                # single container rather than across several.
                dest = ("core-%s" % era if len(here) > 1
                        else "%s-only" % next(iter(here)))
                counts["kept folded"] += 1
                for group in routines(here).values():
                    for name, sources in spellings_of(group, keep_all_spellings):
                        counts["kept folded entries"] += 1
                        counts["entries"] += len(sources)
                        assignments.append((era, guid, dest, name, sources))
                continue
            single = {t: next(iter(n)) for t, n in here.items()}
            if len(single) == 1:
                tag, name = next(iter(single.items()))
                # Kept even when it is a placeholder: one library claiming a
                # GUID cannot be ambiguous with anything, so there is nothing
                # to gain by dropping the only name on offer.
                counts["unique"] += 1
                counts["entries"] += 1
                if PLACEHOLDER.search(name):
                    counts["unique placeholder"] += 1
                assignments.append((era, guid, "%s-only" % tag, name, [tag]))
                continue
            winner = vote(single)
            if winner is None:
                counts["dropped disagreement"] += 1
                continue
            counts["shared"] += 1
            if len(set(single.values())) > 1:
                counts["shared renamed"] += 1
            for name, sources in spellings_of(single, keep_all_spellings):
                counts["entries"] += len(sources)
                assignments.append((era, guid, "core-%s" % era, name, sources))
    return assignments, stats


def read_claims(paths, log=print):
    """`{guid: {tag: {name, ...}}}` for every shipped library in `paths`."""
    from binaryninja import warp
    claims = collections.defaultdict(lambda: collections.defaultdict(set))
    for path in paths:
        tag = os.path.basename(path)[len("delphi-rtl-"):-len(".warp")]
        n = 0
        for chunk in warp.WarpFile(path).chunks:
            for function in chunk.functions:
                claims[str(function.guid)][tag].add(function.name)
                n += 1
        log("read %-10s %7d entries" % (tag, n))
    return claims


def build(sigdir, outdir, keep_all_spellings=False, every_source=False,
          log=print):
    """Read `sigdir`, decide, and write the coalesced libraries to `outdir`.

    `every_source` keeps one entry per library that agreed on a name, instead
    of one entry per name.  It sounds like the right thing -- an entry carries
    the constraints of the release it was built from, so keeping only one
    narrows the library to whichever release the spelling vote favoured -- and
    it is off, because it was built and measured and it loses:

        Demo.exe (D5)          3926-3929 -> 3926-3928, varying names 3 -> 7
        ImageWriterSvc (D12)        3359 -> 3347
        DX.HttpDiag (D13)           1846 -> 1834

    The reason is in the compression pass.  Entries that share a GUID and a
    name are merged into one whose constraint list is the *union* of theirs --
    five staged entries for `System::@Finalize` carrying nine constraints each
    came back as one carrying eleven -- and a longer constraint list is
    strictly harder to satisfy.  So the extra entries do not survive as
    alternatives the matcher can choose between; they survive as one stricter
    entry.  See COALESCE.md.
    """
    import binaryninja as bn
    from binaryninja import warp

    paths = sorted(os.path.join(sigdir, f) for f in os.listdir(sigdir)
                   if f.startswith("delphi-rtl-") and f.endswith(".warp"))
    claims = read_claims(paths, log)
    assignments, stats = plan(claims, keep_all_spellings=keep_all_spellings)
    del claims

    for era in ERAS:
        counts = stats[era]
        log("era %-3s libs=%d guids=%6d claims=%7d -> core %5d (%d respelled)"
            " unique %6d folded %5d as %6d entries (%s) | dropped %5d folded"
            " %5d disagreement"
            % (era, len(ERAS[era]), counts["guids"], counts["claims"],
               counts["shared"], counts["shared renamed"], counts["unique"],
               counts["kept folded"], counts["kept folded entries"],
               FOLDED_POLICY.get(era, "drop"),
               counts["dropped folded"], counts["dropped disagreement"]))
        names = (counts["shared"] + counts["unique"]
                 + counts["kept folded entries"])
        log("        %d names on %d GUIDs, claimed by %d library entries"
            % (names, counts["shared"] + counts["unique"] + counts["folded"]
               - counts["dropped folded"], counts["entries"]))

    # (era, guid) -> (destination, {name: {library, ...}}).  Keyed on the era
    # as well, because a GUID in both era 8 and era 11 is written to both,
    # under whatever spelling each era voted for.  The value maps each name to
    # the libraries whose entry for it is wanted: a kept fold contributes one
    # name per routine in it, and each name contributes one entry per library
    # that agrees on it.
    wanted = {}
    for era, guid, dest, name, sources in assignments:
        names = wanted.setdefault((era, guid), (dest, {}))[1]
        names.setdefault(name, set()).update(sources)
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    with repro.atomic_path(os.path.join(outdir, "plan.tsv")) as temporary:
        with open(temporary, "w") as fh:
            for era, guid, dest, name, sources in sorted(assignments):
                fh.write("%s\t%s\t%s\t%s\t%s\n"
                         % (era, guid, dest, name, ",".join(sources)))

    # One pass per library, keeping only the WarpFunction objects some
    # destination wants.  A function is picked up by the era it belongs to, by
    # a name that era chose, and by being one of the libraries that agreed on
    # that name -- so every agreeing release contributes its own entry, with
    # its own constraints and its own prototype.  Within one library a GUID and
    # name can still appear twice; the typed copy wins, so the coalesced
    # library keeps as many prototypes as the originals had.
    chosen = {}     # destination -> {(guid, name[, tag]): (score, function)}
    for path in paths:
        tag = os.path.basename(path)[len("delphi-rtl-"):-len(".warp")]
        eras = [e for e, t in ERAS.items() if tag in t]
        taken = 0
        for chunk in warp.WarpFile(path).chunks:
            for function in chunk.functions:
                guid = str(function.guid)
                for era in eras:
                    entry = wanted.get((era, guid))
                    if entry is None or tag not in entry[1].get(
                            function.name, ()):
                        continue
                    dest = chosen.setdefault(entry[0], {})
                    key = ((guid, function.name, tag) if every_source
                           else (guid, function.name))
                    score = ((1 if function.type is not None else 0,)
                             if every_source else
                             (1 if function.type is not None else 0,
                              AGE.index(tag)))
                    if key not in dest or dest[key][0] < score:
                        dest[key] = (score, function)
                        taken += 1
        log("selected %-10s %7d entries" % (tag, taken))

    # Two writes, because the two write paths differ in one respect that
    # matters at this size.  A container commits its source verbatim; a
    # `WarpProcessor` deflates the chunk it emits, and `add_path` will take a
    # directory of `.warp` files as its input as readily as a directory of
    # binaries.  So the container writes the selection to `raw/` and the
    # processor rewrites it compressed -- 3.0x smaller, measured, with the
    # same functions in it.
    raw = os.path.join(outdir, "raw")
    if not os.path.isdir(raw):
        os.makedirs(raw)
    target = warp.WarpTarget.from_platform(bn.Platform["windows-x86"])
    written = []
    for dest in sorted(chosen):
        out = os.path.join(raw, "delphi-rtl-%s.warp" % dest)
        if os.path.exists(out):
            os.remove(out)
        functions = [f for _, f in chosen[dest].values()]
        container = warp.WarpContainer.add("Coalesce %s" % dest)
        source = container.add_source(out)
        if source is None:
            raise RuntimeError("could not create source %s" % out)
        if not container.add_functions(target, source, functions):
            raise RuntimeError("could not add functions to %s" % out)
        if not container.commit_source(source):
            raise RuntimeError("could not commit %s" % out)
        log("staged %-24s %7d functions %9d bytes"
            % (os.path.basename(out), len(functions), os.path.getsize(out)))
        written.append(out)
    return written


def compress_all(outdir, log=print):
    """Second pass: deflate every staged library under `outdir/raw`.

    A separate process from `build`, deliberately.  `build` leaves nineteen
    containers registered in the one it runs in, and a `WarpProcessor` shares
    the process with them; keeping the two apart means the compressed output
    cannot depend on what the staging run happened to register.
    """
    raw = os.path.join(outdir, "raw")
    return [compress(os.path.join(raw, f), outdir, log)
            for f in sorted(os.listdir(raw)) if f.endswith(".warp")]


def compress(path, outdir, log=print):
    """Rewrite one staged library through a `WarpProcessor`, deflated.

    One processor per file and one file per directory: `add_path` takes a
    directory, and everything under it lands in one output, which is exactly
    what must not happen to libraries that were just separated.
    """
    import binaryninja as bn
    from binaryninja import warp
    solo = os.path.join(outdir, "raw", "_one")
    if not os.path.isdir(solo):
        os.makedirs(solo)
    for stale in os.listdir(solo):
        os.remove(os.path.join(solo, stale))
    staged = os.path.join(solo, os.path.basename(path))
    shutil.copyfile(path, staged)
    processor = warp.WarpProcessor()
    processor.add_path(solo)
    warp_file = processor.start()
    if warp_file is None:
        raise RuntimeError("processor produced nothing for %s" % path)
    out = os.path.join(outdir, os.path.basename(path))
    build = repro.build_manifest(
        "coalesced-delphi-warp",
        {"raw_library": repro.file_inventory([path]),
         "plan": repro.file_inventory([os.path.join(outdir, "plan.tsv")])},
        {"eras": list(ERAS.items()), "folded_policy": FOLDED_POLICY},
        repro.file_inventory([__file__], os.path.dirname(__file__)),
        {"binary_ninja": bn.core_version()})
    with repro.atomic_path(out) as temporary:
        with open(temporary, "wb") as handle:
            handle.write(bytes(warp_file.to_data_buffer()))
    repro.write_artifact_manifest(out, build)
    log("wrote  %-24s %7d functions %9d bytes (%.1fx)"
        % (os.path.basename(out),
           sum(len(c.functions) for c in warp_file.chunks),
           os.path.getsize(out),
           float(os.path.getsize(path)) / max(os.path.getsize(out), 1)))
    return out


def verify(outdir, log=print):
    """Read the written libraries back and hold them to `plan.tsv`.

    Three ways this could go wrong quietly, so all three are checked: a
    function could be lost in the staging or the compression pass, a
    destination could keep the wrong spelling, and -- the one that would put
    the nondeterminism straight back -- two libraries of one era could still
    claim the same GUID.

    What is enforced is the set of *names* on each GUID, not the number of
    entries.  The compression pass merges entries that share a GUID and a name,
    unioning their constraints rather than dropping them -- measured on
    `System::@Finalize`, five staged entries carrying nine constraints each
    came back as one carrying eleven -- so a file built with `--every-source`
    legitimately holds fewer entries than the plan asked for.
    """
    from binaryninja import warp
    # destination -> {guid: {name: how many entries}}.  Two reasons a GUID
    # carries more than one entry: a kept fold is several routines under
    # several names, and a name several libraries agreed on is kept once per
    # library, so the count matters as much as the set.
    expected = collections.defaultdict(
        lambda: collections.defaultdict(collections.Counter))
    for line in open(os.path.join(outdir, "plan.tsv")):
        era, guid, dest, name, sources = line.rstrip("\n").split("\t")
        expected[dest][guid][name] += len(sources.split(","))
    actual = {}
    for f in sorted(os.listdir(outdir)):
        if not (f.startswith("delphi-rtl-") and f.endswith(".warp")):
            continue
        dest = f[len("delphi-rtl-"):-len(".warp")]
        got = collections.defaultdict(collections.Counter)
        for chunk in warp.WarpFile(os.path.join(outdir, f)).chunks:
            for function in chunk.functions:
                got[str(function.guid)][function.name] += 1
        actual[dest] = got
    bad = 0
    for dest, want in sorted(expected.items()):
        got = actual.get(dest, {})
        missing = set(want) - set(got)
        extra = set(got) - set(want)
        wrong = [g for g in set(want) & set(got) if set(got[g]) != set(want[g])]
        bad += len(missing) + len(extra) + len(wrong)
        log("%-24s %7d GUIDs / %7d names wanted, %7d / %7d entries present, "
            "%d missing, %d extra, %d misnamed"
            % (dest, len(want), sum(len(n) for n in want.values()),
               len(got), sum(sum(n.values()) for n in got.values()),
               len(missing), len(extra), len(wrong)))
    for era, tags in ERAS.items():
        dests = [d for d in actual
                 if d == "core-%s" % era or d[:-len("-only")] in tags]
        seen = {}
        clash = 0
        for d in dests:
            for guid in actual[d]:
                if guid in seen:
                    clash += 1
                seen[guid] = d
        bad += clash
        log("era %-3s %d libraries, %d GUIDs, %d claimed twice"
            % (era, len(dests), len(seen), clash))
    log("verify: %s" % ("OK" if bad == 0 else "%d PROBLEMS" % bad))
    return bad


def main(argv):
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args = [a for a in argv[1:] if not a.startswith("--")]
    outdir = args[0] if args else os.path.join(root, "signatures-new")
    if "--verify" in argv:
        sys.exit(1 if verify(outdir) else 0)
    elif "--compress" in argv:
        compress_all(outdir)
    else:
        # The per-release libraries are this tool's input and are no longer in
        # `signatures/`: coalescing superseded them and they were deleted.
        # `git show <commit>:signatures/delphi-rtl-<tag>.warp` still has every
        # one of them, and the second argument points the build at wherever
        # they were extracted to.
        source = args[1] if len(args) > 1 else os.path.join(root, "signatures")
        build(source, outdir,
              keep_all_spellings="--all-spellings" in argv,
              every_source="--every-source" in argv)


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        main(sys.argv)
    else:
        import binaryninja as bn
        bn.disable_default_log()
        main(sys.argv)
