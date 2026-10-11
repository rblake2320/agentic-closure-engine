"""Content-addressed evidence with bounded reads and verified atomic creation."""

import os
import tempfile
from pathlib import Path

from .protocol import MAX_BYTES, ClosureError, digest


class EvidenceStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, evidence_hash):
        if (
            not isinstance(evidence_hash, str)
            or len(evidence_hash) != 71
            or not evidence_hash.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in evidence_hash[7:])
        ):
            raise ClosureError("INVALID_EVIDENCE_REFERENCE")
        path = self.root / evidence_hash[7:]
        if path.is_symlink():
            raise ClosureError("UNSAFE_EVIDENCE_PATH")
        return path

    def put(self, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
            raise ClosureError("INPUT_TOO_LARGE")
        evidence_hash = digest(raw)
        path = self.path_for(evidence_hash)
        if path.exists():
            self.get(evidence_hash)
            return evidence_hash
        fd, temp = tempfile.mkstemp(prefix=".pending-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            # Create without replacing another accepted object.
            try:
                os.link(temp, path)
            except FileExistsError:
                self.get(evidence_hash)
            self.get(evidence_hash)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        return evidence_hash

    def get(self, evidence_hash):
        path = self.path_for(evidence_hash)
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        except FileNotFoundError as exc:
            raise ClosureError("EVIDENCE_MISSING") from exc
        except OSError as exc:
            raise ClosureError("EVIDENCE_STORAGE_UNAVAILABLE") from exc
        if len(raw) > MAX_BYTES or digest(raw) != evidence_hash:
            raise ClosureError("EVIDENCE_HASH_MISMATCH")
        return raw
