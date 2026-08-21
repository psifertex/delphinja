"""Register the signature libraries that ship with this plugin.

Binary Ninja seeds WARP's container cache from two directories on disk,
[install]/signatures and [user]/signatures, and there is no setting for adding
a third. A plugin is not stuck copying files into the user's signature
directory, though: BNWARPAddContainer creates a container in that same cache,
and a container accepts a source at any absolute path. That is what this does,
so the libraries stay inside the plugin and are picked up wherever the plugin
happens to be installed.

Two properties of the cache shape the code below. It is keyed on the container
name, so a colliding name silently replaces someone else's container -- hence
the plugin-qualified name. And it is per-process rather than persisted, so this
runs at every launch and writes nothing.
"""

import os

import binaryninja as bn

CONTAINER = "Delphinja Signatures"

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "signatures")


def bundled():
    """Absolute paths of the .warp libraries shipped with the plugin."""
    if not os.path.isdir(_DIR):
        return []
    return sorted(os.path.join(_DIR, f) for f in os.listdir(_DIR)
                  if f.endswith(".warp"))


def register(tag="Delphinja"):
    """Add the bundled libraries to WARP's container cache.

    Returns the number of libraries registered. Failure here must not stop the
    rest of the plugin loading: WARP is a core plugin and can be disabled, in
    which case binaryninja.warp is missing entirely, and a signature library
    is an enhancement rather than a prerequisite for anything else here.
    """
    files = bundled()
    if not files:
        return 0
    try:
        from binaryninja import warp
    except ImportError:
        bn.log_warn("WARP is unavailable; %d bundled signature librar%s not "
                    "registered" % (len(files), "y was" if len(files) == 1
                                    else "ies were"), tag)
        return 0
    try:
        container = warp.WarpContainer.add(CONTAINER)
        for path in files:
            container.add_source(path)
    except Exception as exc:
        bn.log_error("could not register bundled signatures: %s" % exc, tag)
        return 0
    bn.log_info("registered %d bundled Delphi signature librar%s"
                % (len(files), "y" if len(files) == 1 else "ies"), tag)
    return len(files)
