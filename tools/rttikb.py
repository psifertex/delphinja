"""A knowledge base harvested from binaries, for the Delphi releases IDR never
covered.

The Delphi and Free Pascal pipelines both start from a shipped artifact -- an
IDR knowledge base, an FPC release's `.o` files -- that states name, bytes and
relocations for every routine.  For Delphi 10 Seattle onwards no such artifact
exists: IDR's knowledge bases stop at XE6, and nothing else publishes the
compiled RTL outside a Delphi installation.

What a post-2014 binary does publish is its own extended RTTI.  Since Delphi
2010 the compiler emits a second method array beside the VMT holding the name
and address of every public and published method of every class the binary
links, RTL classes included -- so `System.Classes.TStrings.AddStrings` is named
by the binary that uses it, with no reference to any library.  That is a name
and an address; the bytes are in the same file.  It is a knowledge base with
one property the shipped ones do not have: it is *per binary*, so the same
routine can be read out of many independent programs and the readings compared.

That comparison is the whole design.  A reading is admitted only when several
unrelated programs, built by unrelated people, independently produce the same
name for the same code -- where "the same code" is WARP's own function GUID,
which is the equivalence the matcher will use anyway, so agreement here means
agreement at match time.  And a GUID that two different names claim anywhere in
the harvest is discarded outright, because that is what a name collision looks
like from the inside and there is no way to tell which name was meant.

What this cannot recover, and the shipped knowledge bases can:

* **Unit-level procedures.**  Extended RTTI describes classes.  A bare
  `procedure` in `System.SysUtils` has no metadata anywhere and cannot be
  reached this way.
* **Private and protected methods.**  The RTL compiles with the default
  `{$RTTI EXPLICIT METHODS([vcPublic, vcPublished])}`, so a private virtual is
  in the VMT but not in the method array.
* **Prototypes.**  The extended method entry carries a parameter list only for
  published methods, and the existing decoder does not read it, so functions
  here are named but untyped.

So this is a narrower library than an IDR-derived one, built out of what a
binary is willing to say about itself.  It is additive: it names methods that
would otherwise stay `sub_`, and it claims nothing it cannot corroborate.
"""

import collections
import os

from . import naming

# Units a Delphi installation ships, by the first component of the unit name.
#
# The consensus rule alone would admit any third-party unit that several corpus
# projects happen to share, and those names would be just as correct -- but a
# library called `delphi-rtl` should hold the RTL, and a third-party unit is not
# version-pinned to the compiler, so its code varies for reasons this pipeline
# has no way to see.  The list is the namespace roots Embarcadero reserves,
# which is exactly the set that moves with the compiler.
RTL_NAMESPACES = frozenset((
    "System", "Vcl", "Fmx", "Winapi", "Data", "Datasnap", "Soap", "Xml",
    "Web", "Bde", "IBX", "FireDAC", "REST", "Posix", "Macapi", "Androidapi",
))


def qualify(unit, cls, member):
    """`System.Classes::TStrings::AddStrings` -- `naming.qualify`, verbatim
    unit.

    The dotted unit is not a stylistic choice.  From XE2 the RTL's `.dcu`
    files are named for the namespaced unit, so `generate.display_units` reads
    `System.Classes` out of an IDR knowledge base and the shipped
    `delphi-rtl-2011`..`2014` libraries already spell it that way.  Both
    libraries are loaded for the same binaries, and where they describe the
    same code they must produce the same string: two libraries claiming one
    GUID under two spellings is an ambiguity the matcher resolves by declining
    the match, so a cosmetic difference here costs matches in the *existing*
    libraries.

    The class's dots stay put for the same reason they do there -- a generic
    class name carries its type arguments verbatim, as in
    `TDictionary<System.string,System.Classes.TPersistentClass>.TPairEnumerator`.
    """
    return naming.qualify(unit, cls, member)


def is_rtl(unit):
    return unit.split(".", 1)[0] in RTL_NAMESPACES


def binary_names(record, unit_source="rtti"):
    """`{address: qualified name}` for one harvested binary.

    Two claims are refused here rather than deferred to the consensus:

    A unit inferred from neighbouring metadata (`unit_source == "nearby"`) is a
    guess about which unit a class belongs to.  It is a good guess for reading
    a single binary, where a wrong unit still leaves the class name right; it
    is not good enough to decide whether a class is RTL at all, which is what
    this uses the unit for.

    An address two different names claim inside one binary is evidence that the
    linker folded two methods onto one body -- so it is evidence against both
    names, not for either.
    """
    names = collections.defaultdict(set)
    for entry in record["entries"]:
        for unit, source, cls, member in entry["claims"]:
            if unit and source == unit_source and is_rtl(unit):
                names[entry["addr"]].add(qualify(unit, cls, member))
    return {addr: next(iter(n)) for addr, n in names.items() if len(n) == 1}


def project(path):
    """The corpus directory a binary came from, which is one voter.

    Votes are counted per project, not per file, because the corpus holds an
    application and its installer, and two releases of the same program, in one
    directory.  Those are one piece of evidence: they were built by the same
    person from the same sources with the same compiler, and a mistake in one
    is a mistake in both.  Counting files would let a single project reach a
    three-binary threshold on its own.
    """
    return os.path.basename(os.path.dirname(path))


class Consensus(object):
    """The readings several independent projects agree on.

    `votes` maps a (name, GUID) pair to the projects that produced it, and
    `guid_names` maps a GUID to every name any binary gave it.  A pair is kept
    when enough projects voted for it and no other name ever claimed its GUID.
    """

    def __init__(self, min_projects=3, min_blocks=2):
        self.min_projects = min_projects
        # A single-basic-block body is usually a field getter or a jump, and
        # thousands of them share one shape; they are the bulk of what the
        # uniqueness filter rejects anyway, and dropping them first keeps the
        # rejection from being reported as a collision.
        self.min_blocks = min_blocks
        self.votes = collections.defaultdict(set)
        self.guid_names = collections.defaultdict(set)
        self.sources = {}

    def add(self, record):
        by_addr = {e["addr"]: e for e in record["entries"]}
        for addr, name in binary_names(record).items():
            entry = by_addr[addr]
            if entry["blocks"] < self.min_blocks:
                continue
            self.votes[(name, entry["guid"])].add(project(record["file"]))
            # Every binary's reading counts against a GUID's uniqueness, even
            # one whose vote is redundant: a second name for a GUID is a fact
            # about the code, and it disqualifies the GUID no matter which
            # project noticed it.
            self.guid_names[entry["guid"]].add(name)
            self.sources.setdefault((name, entry["guid"]), []).append(
                (record["file"], addr))
        return self

    def ambiguous(self):
        """GUIDs more than one name claims -- a fold, or two bodies that WARP
        cannot tell apart.  Either way the name is not recoverable."""
        return {g for g, n in self.guid_names.items() if len(n) > 1}

    def keep(self, shipped=frozenset()):
        """(name, guid) -> [(binary, address), ...] for every kept reading.

        `shipped` is every GUID the already-published libraries claim, and a
        reading whose GUID is in it is dropped whether or not the two agree on
        the name.  Both outcomes argue for dropping it.  A library is selected
        by era, not by release, so this one is loaded alongside the 2009-2014
        libraries for every Unicode-era binary; two loaded libraries claiming
        one GUID under two names is the ambiguity the matcher resolves by
        declining the match, so a disagreement would cost a match the shipped
        library was already making.  And where they agree the entry is
        redundant -- the shipped one carries a prototype as well as a name.

        Measured against `delphi-rtl-2011`..`2014`: of 673 readings whose GUID
        those libraries also carry, 49 were named differently, and every one of
        those was a body too generic to identify -- an empty constructor, a
        one-line accessor -- that two unrelated classes happen to share.
        Dropping the whole overlap leaves the new library strictly additive.
        """
        bad = self.ambiguous()
        return {k: v for k, v in self.sources.items()
                if k[1] not in bad and k[1] not in shipped
                and len(self.votes[k]) >= self.min_projects}

    def report(self, shipped=frozenset()):
        bad = self.ambiguous()
        enough = [k for k in self.votes if len(self.votes[k]) >= self.min_projects]
        kept = self.keep(shipped)
        return collections.OrderedDict((
            ("candidates", len(self.votes)),
            ("corroborated", len(enough)),
            ("dropped_ambiguous", len([k for k in enough if k[1] in bad])),
            ("dropped_shipped", len([k for k in enough
                                     if k[1] not in bad and k[1] in shipped])),
            ("kept", len(kept)),
            ("names", len({k[0] for k in kept})),
            ("guids", len({k[1] for k in kept})),
        ))


def cover(keep, limit=None):
    """The fewest binaries that between them hold every kept reading.

    The library is generated from real binaries -- each kept reading has to be
    pointed at as a function in some view -- and every extra view is another
    whole program held in memory during generation.  Greedy set cover is not
    optimal, but the distribution is steeply skewed (a handful of large
    programs link most of the RTL), so it gets within a view or two of optimal
    and the remainder is a long tail of one-reading binaries.

    Returns [(binary, {(name, guid): address})], most productive first.
    """
    remaining = dict(keep)
    chosen = []
    while remaining and (limit is None or len(chosen) < limit):
        offers = collections.defaultdict(dict)
        for key, places in remaining.items():
            for path, addr in places:
                offers[path].setdefault(key, addr)
        # Stable path order breaks equal-coverage ties.  Depending on dict
        # insertion here changes which binaries feed WARP and therefore makes
        # an otherwise identical rebuild choose different inputs.
        path, take = min(offers.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        if not take:
            break
        chosen.append((path, take))
        for key in take:
            del remaining[key]
    return chosen, remaining
