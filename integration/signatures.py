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
across 30 corpus binaries, loading only the era-appropriate libraries matched
*more* functions on 11 of them than loading all fifteen, because several
libraries claiming the same function GUID leaves the matcher unable to choose
and it declines the match.
"""

import os

import binaryninja as bn

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "signatures")

# Virtual method table header size -> the knowledge base tags whose libraries
# can plausibly match. The header size is what the decoder already detects per
# binary, and it separates the eras cleanly: 64 bytes is Delphi 2, 76 covers
# Delphi 3 through 2007, and 88 is Delphi 2009 and later.
#
# This narrows the field; it does not pick a single version, because nothing
# cheaply readable in the binary identifies one. The linker version is 2.25
# across the whole range and the vendor string only tells Borland-era from
# Embarcadero-era, which is the same split the header size already gives.
ERAS = {
    64: ["2"],
    76: ["3", "4", "5", "6", "7", "2005", "2006", "2007"],
    88: ["2009", "2010", "2011", "2012", "2013", "2014"],
}

_registered = set()


def library(tag):
    """Absolute path of the library for a knowledge base tag, if it ships."""
    path = os.path.join(_DIR, "delphi-rtl-%s.warp" % tag)
    return path if os.path.exists(path) else None


def bundled():
    """Absolute paths of every .warp library shipped with the plugin."""
    if not os.path.isdir(_DIR):
        return []
    return sorted(os.path.join(_DIR, f) for f in os.listdir(_DIR)
                  if f.endswith(".warp"))


def tags_for(header_size):
    """Knowledge base tags worth loading for a binary with this VMT header."""
    return ERAS.get(header_size, [])


def register(tags, tag="Delphinja"):
    """Register the named libraries, skipping any already registered.

    Returns the tags newly registered. Failure must not stop analysis: WARP is
    a core plugin and can be disabled, in which case binaryninja.warp is not
    importable at all, and signatures are an enhancement rather than a
    prerequisite for anything else here.
    """
    wanted = [t for t in tags if t not in _registered and library(t)]
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
        _registered.update(tags)          # do not retry on every binary
        return []
    done = []
    for t in wanted:
        try:
            container = warp.WarpContainer.add("Delphinja delphi-rtl-%s" % t)
            container.add_source(library(t))
        except Exception as exc:
            bn.log_error("could not register signature library %s: %s" % (t, exc), tag)
            continue
        _registered.add(t)
        done.append(t)
    if done:
        bn.log_info("registered Delphi signature librar%s %s"
                    % ("y" if len(done) == 1 else "ies", ", ".join(done)), tag)
    return done


def register_for(header_size, tag="Delphinja"):
    """Register the libraries appropriate to a detected VMT header size."""
    tags = tags_for(header_size)
    if not tags:
        bn.log_debug("no signature libraries for VMT header size %r" % (header_size,), tag)
        return []
    return register(tags, tag)


def register_all(tag="Delphinja"):
    """Register every bundled library. For comparison runs, not for normal use."""
    all_tags = [os.path.basename(p)[len("delphi-rtl-"):-len(".warp")]
                for p in bundled()]
    return register(all_tags, tag)
