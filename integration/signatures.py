"""Register bundled signature libraries, on demand, for the binary in hand.

Binary Ninja seeds WARP's container cache from two directories on disk,
[install]/signatures and [user]/signatures, and there is no setting for adding
a third. A plugin is not stuck copying files into the user's signature
directory, though: BNWARPAddContainer creates a container in that same cache,
and a container accepts a source at any absolute path. That is what this does,
so the libraries stay inside the plugin and are picked up wherever the plugin
happens to be installed.

Three properties of the cache shape the code below.

It is keyed on the container name, so a colliding name silently replaces
someone else's container -- hence the plugin-qualified names.

It is additive: nothing in the API removes a source or unloads a container
(`remove_functions`/`remove_types` operate on a container's contents, not on
its sources). So a library, once registered, stays for the life of the
process. That is why registration is deferred until a binary actually calls
for one, rather than done at plugin load.

And it reads a container's sources when the container is created. Each library
therefore gets its own container, created complete, instead of one container
gaining sources over time.

Loading every library at once measurably costs matches as well as precision:
across 30 corpus binaries, loading only the version-matched library matched
*more* functions on 11 of them than loading all fifteen, because several
libraries claiming the same function GUID leaves the matcher unable to choose
and it declines the match. Narrowing the set is therefore the point of the
selection below.
"""

import os
import re

import binaryninja as bn

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "signatures")

_registered = set()


# Free Pascal ships its own runtime, unrelated to Delphi's, so it needs its own
# libraries and its own detection. Unlike Delphi -- where nothing cheaply
# readable gives the version -- an FPC binary states it outright, so this
# selects one library rather than an era's worth.
#
# The gate is a section named .CRT, which every one of the 41 FPC binaries in
# the corpus has and no Delphi binary does. That keeps the cost of asking "is
# this Free Pascal?" to a single section lookup on everything else.
FPC_SERIES = {
    "2.6": "2.6.4", "2.7": "2.6.4",          # 2.7.x is the 2.8 development line
    "3.0": "3.0.4", "3.1": "3.0.4",          # 3.1.x is the 3.2 development line
    "3.2": "3.2.2", "3.3": "3.2.2",
}
FPC_DEFAULT = "3.2.2"       # still the current stable release

# The version marker, as a byte-level regular expression for BinaryView.search.
# The whole pattern goes to the core, rather than searching for the literal
# "FPC" and testing each hit in Python: a Free Pascal binary can carry many
# dozens of "FPC" substrings ahead of the version string, so a Python-side
# test needs a hit budget, and any budget small enough to be cheap is one a
# real binary can exhaust before reaching the marker.
_FPC_PATTERN = r"FPC[ /-](\d+)\.(\d+)\.(\d+)"
_FPC_GROUPS = re.compile(rb"FPC[ /-](\d+)\.(\d+)\.(\d+)")


def library(tag):
    """Absolute path of the library for a knowledge base tag, if it ships."""
    path = os.path.join(_DIR, "delphi-rtl-%s.warp" % tag)
    return path if os.path.exists(path) else None


def fpc_library(tag):
    """Absolute path of a Free Pascal library tag like "3.2.2-win32"."""
    path = os.path.join(_DIR, "fpc-rtl-%s.warp" % tag)
    return path if os.path.exists(path) else None


def fpc_version(bv):
    """The FPC release that built this binary, or None if it is not FPC.

    Returns the version as written in the binary, e.g. "3.2.2".

    The whole pattern goes to BinaryView.search, which matches it in the core
    at memory bandwidth and hands back the matched bytes, rather than the core
    finding "FPC" and Python re-testing every hit across the view lock.
    """
    try:
        if bv.get_section_by_name(".CRT") is None:
            return None
    except Exception:
        return None
    match = _first_match(bv, _FPC_PATTERN)
    if match is None:
        return None
    m = _FPC_GROUPS.match(match)
    return b".".join(m.groups()).decode() if m else None


def _first_match(bv, pattern):
    """The bytes of the first match of `pattern`, or None.

    `search` runs the scan on a worker thread and publishes matches on a
    queue; `limit=1` stops the scan at the first one. The generator is taken
    exactly one step: an exhausted search generator does not survive a second
    `next`.
    """
    found = next(iter(bv.search(pattern, limit=1)), None)
    return bytes(found[1]) if found else None


def fpc_tags(bv):
    """The Free Pascal library tags to load for this binary, if any."""
    version = fpc_version(bv)
    if version is None:
        return []
    series = ".".join(version.split(".")[:2])
    release = FPC_SERIES.get(series, FPC_DEFAULT)
    arch = "win64" if bv.arch is not None and bv.arch.address_size == 8 else "win32"
    tag = "%s-%s" % (release, arch)
    if fpc_library(tag):
        return [tag]
    # No library for that architecture; the other one cannot match at all.
    bn.log_debug("no Free Pascal signature library for %s" % tag, "Delphinja")
    return []


def bundled():
    """Absolute paths of every .warp library shipped with the plugin."""
    if not os.path.isdir(_DIR):
        return []
    return sorted(os.path.join(_DIR, f) for f in os.listdir(_DIR)
                  if f.endswith(".warp"))


# The VMT layout is the one piece of version evidence a Delphi binary gives up
# cheaply, and it names an era rather than a release: TObject gained virtual
# slots at Delphi 3, at Delphi 4 and at Delphi 2009, and has not since. An era
# is as far as that evidence goes -- but it is the narrowing that matters,
# because the libraries that cost a match are the ones from a *different* era
# claiming the same function GUID, and those are exactly what this rules out.
#
# Keyed on the standard TObject virtual slot count, which is what
# `detect_layout` already measures. Four is Delphi 2, whose layout this build
# cannot detect yet -- it has no vmtSelfPtr to anchor on -- and the entry is
# here so that adding that layout does not also need a change here.
DELPHI_ERAS = {
    4: ["2"],
    5: ["3"],
    8: ["4", "5", "6", "7", "2005", "2006", "2007"],
    11: ["2009", "2010", "2011", "2012", "2013", "2014"],
    # Nothing ships past the 2014 knowledge base, so a later era gets the
    # newest libraries rather than none: a near miss can still match, and no
    # library at all certainly cannot.
    14: ["2009", "2010", "2011", "2012", "2013", "2014"],
}


def delphi_tags(layout=None):
    """The Delphi knowledge base tags to load for a binary of this layout.

    With no layout -- a caller that has not scanned, or an era this build does
    not recognise -- every shipped library is the honest answer. Loading one
    that cannot match costs a lookup; failing to load one that could have
    matched costs the match itself, so breadth is the safer failure.
    """
    shipped = [os.path.basename(p)[len("delphi-rtl-"):-len(".warp")]
               for p in bundled() if os.path.basename(p).startswith("delphi-rtl-")]
    era = DELPHI_ERAS.get(layout.n_virtuals) if layout is not None else None
    return shipped if era is None else [t for t in shipped if t in era]


def register_fpc(bv, tag="Delphinja"):
    """Register the Free Pascal library matching this binary, if any."""
    return register(fpc_tags(bv), tag, kind="fpc")


def register(tags, tag="Delphinja", kind="delphi"):
    """Register the named libraries, skipping any already registered.

    Returns the tags newly registered. Failure must not stop analysis: WARP is
    a core plugin and can be disabled, in which case binaryninja.warp is not
    importable at all, and signatures are an enhancement rather than a
    prerequisite for anything else here.
    """
    find = fpc_library if kind == "fpc" else library
    wanted = [t for t in tags if (kind, t) not in _registered and find(t)]
    if not wanted:
        return []
    # Checked here rather than at import: the setting is registered during
    # plugin load, and nothing loads a library until a binary asks for one.
    if not bn.Settings().get_bool("delphinja.signatures"):
        return []
    try:
        from binaryninja import warp
    except ImportError:
        bn.log_warn("WARP is unavailable; bundled signatures not registered", tag)
        _registered.update((kind, t) for t in tags)   # do not retry per binary
        return []
    done = []
    for t in wanted:
        try:
            stem = ("fpc-rtl-%s" if kind == "fpc" else "delphi-rtl-%s") % t
            container = warp.WarpContainer.add("Delphinja %s" % stem)
            container.add_source(find(t))
        except Exception as exc:
            bn.log_error("could not register signature library %s: %s" % (t, exc), tag)
            continue
        _registered.add((kind, t))
        done.append(t)
    if done:
        bn.log_info("registered %s signature librar%s %s"
                    % ("Free Pascal" if kind == "fpc" else "Delphi",
                       "y" if len(done) == 1 else "ies", ", ".join(done)), tag)
    return done


def register_delphi(layout=None, tag="Delphinja"):
    """Register the bundled Delphi libraries that can match this binary.

    `layout` is the one `detect_layout` settled on; passing it narrows fifteen
    libraries to the era's own, which is the point of the selection this
    module's docstring describes. Omitting it falls back to registering
    everything, which is what a caller with no scan behind it can honestly do.
    """
    return register(delphi_tags(layout), tag)
