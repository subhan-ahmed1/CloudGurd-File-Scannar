"""File integrity hashing.

Streams the file in chunks so arbitrarily large uploads do not need to be
held in memory all at once.
"""
import hashlib


def compute_hashes(path: str, chunk_size: int = 65536) -> dict:
    """Return MD5 and SHA-256 hex digests for the file at ``path``."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)

    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
