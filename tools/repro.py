"""Pure helpers for reproducible build inputs, caches, and manifests.

This module deliberately imports no Binary Ninja APIs.  Build entry points can
therefore share one implementation, and the invariants can be exercised by the
license-free test suite.
"""

from contextlib import contextmanager
import hashlib
import json
import os
import tempfile
import urllib.request


MANIFEST_VERSION = 1


class VerificationError(RuntimeError):
    """An artifact did not match its pinned publisher metadata."""


def _hash(name):
    try:
        return hashlib.new(name, usedforsecurity=False)
    except TypeError:  # Python versions without the FIPS compatibility flag.
        return hashlib.new(name)


def file_hash(path, algorithm="sha256"):
    digest = _hash(algorithm)
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_blob_hash(path):
    """Return Git's SHA-1 blob ID, which includes the object header."""
    size = os.path.getsize(path)
    digest = _hash("sha1")
    digest.update(("blob %d\0" % size).encode("ascii"))
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_file(path, expected):
    """Return whether ``path`` matches all supplied size/hash constraints."""
    try:
        if "size" in expected and os.path.getsize(path) != expected["size"]:
            return False
        for algorithm in ("sha256", "sha1", "md5"):
            wanted = expected.get(algorithm)
            if wanted and file_hash(path, algorithm) != wanted.lower():
                return False
        wanted = expected.get("git_blob_sha1")
        if wanted and git_blob_hash(path) != wanted.lower():
            return False
        return os.path.isfile(path)
    except OSError:
        return False


def require_verified(path, expected):
    if not verify_file(path, expected):
        raise VerificationError("%s does not match its pinned size/checksum"
                                % path)
    return path


@contextmanager
def atomic_path(destination):
    """Yield a same-directory temporary path and replace on clean exit."""
    directory = os.path.dirname(os.path.abspath(destination))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".%s." % os.path.basename(destination), dir=directory)
    os.close(fd)
    try:
        yield temporary
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def atomic_write(destination, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    with atomic_path(destination) as temporary:
        with open(temporary, "wb") as handle:
            handle.write(data)


def canonical_json(data):
    return (json.dumps(data, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def atomic_json(destination, data):
    atomic_write(destination, canonical_json(data))


def fetch_verified(url, destination, expected, retrieve=None):
    """Reuse a verified download or atomically replace a stale/corrupt one."""
    if verify_file(destination, expected):
        return destination
    retrieve = retrieve or urllib.request.urlretrieve
    with atomic_path(destination) as temporary:
        retrieve(url, temporary)
        require_verified(temporary, expected)
    return destination


def file_inventory(paths, base=None):
    """Describe file names and contents in deterministic order.

    Paths are relative to their common directory by default, keeping a build
    identity stable when an otherwise identical source tree moves.
    """
    paths = sorted(os.path.abspath(path) for path in set(paths))
    if not paths:
        return []
    if base is None:
        base = os.path.commonpath(paths)
        if os.path.isfile(base):
            base = os.path.dirname(base)
    base = os.path.abspath(base)
    return [{"path": os.path.relpath(path, base).replace(os.sep, "/"),
             "size": os.path.getsize(path),
             "sha256": file_hash(path)} for path in paths]


def inventory_matches(paths, expected, base=None):
    try:
        return file_inventory(paths, base) == expected
    except OSError:
        return False


def common_base(paths):
    paths = [os.path.abspath(path) for path in paths]
    if not paths:
        return os.curdir
    base = os.path.commonpath(paths)
    return os.path.dirname(base) if os.path.isfile(base) else base


def logical_path(path, base):
    return os.path.relpath(os.path.abspath(path),
                           os.path.abspath(base)).replace(os.sep, "/")


def content_cache_manifest(kind, source, source_base, tools, tool_base,
                           settings, runtime=None):
    """Portable, collision-resistant identity for one source-file cache."""
    return build_manifest(
        kind, {"source": file_inventory([source], source_base)}, settings,
        file_inventory(tools, tool_base), runtime)


def build_manifest(kind, inputs, settings, tools, runtime=None):
    manifest = {
        "format": MANIFEST_VERSION,
        "kind": kind,
        "inputs": inputs,
        "settings": settings,
        "tools": tools,
    }
    if runtime:
        manifest["runtime"] = runtime
    return manifest


def manifest_stamp(manifest):
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def artifact_manifest(path, build):
    return {
        "format": MANIFEST_VERSION,
        "artifact": {
            "name": os.path.basename(path),
            "size": os.path.getsize(path),
            "sha256": file_hash(path),
        },
        "build": build,
        "stamp": manifest_stamp(build),
    }


def manifest_path(path):
    return os.fspath(path) + ".manifest.json"


def write_artifact_manifest(path, build):
    document = artifact_manifest(path, build)
    atomic_json(manifest_path(path), document)
    return document


def artifact_is_current(path, build):
    try:
        with open(manifest_path(path), encoding="utf-8") as handle:
            document = json.load(handle)
        return (document.get("build") == build
                and document.get("stamp") == manifest_stamp(build)
                and verify_file(path, document["artifact"]))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def cache_path(cachedir, source, build):
    """A collision-resistant cache name tied to source and tool identity."""
    name = os.path.basename(source)
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
    return os.path.join(cachedir, "%s-%s.json"
                        % (safe, manifest_stamp(build)[:24]))


def read_cache(path, build):
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        record = document["record"]
        record_hash = hashlib.sha256(canonical_json(record)).hexdigest()
        if (document.get("build") == build
                and document.get("stamp") == manifest_stamp(build)
                and document.get("record_sha256") == record_hash):
            return record
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def write_cache(path, build, record):
    atomic_json(path, {
        "build": build,
        "record": record,
        "record_sha256": hashlib.sha256(canonical_json(record)).hexdigest(),
        "stamp": manifest_stamp(build),
    })
