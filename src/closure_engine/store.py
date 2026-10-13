"""Content-addressed evidence with bounded reads and verified atomic creation."""

import os
import sys
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path

from .protocol import MAX_BYTES, ClosureError, canonical, digest, strict_loads


class EvidenceStore:
    def __init__(self, root, *, create=True, replay_cache_entries=8192, replay_cache_bytes=64 * 1024 * 1024):
        self.root = Path(root).resolve()
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        elif not self.root.is_dir():
            # Verification reads existing custody; a mistyped path must not become an empty store.
            raise ClosureError("EVIDENCE_STORE_MISSING", str(self.root))
        if (
            type(replay_cache_entries) is not int
            or not 0 <= replay_cache_entries <= 8192
            or type(replay_cache_bytes) is not int
            or not 0 <= replay_cache_bytes <= 64 * 1024 * 1024
        ):
            raise ClosureError("REPLAY_CACHE_LIMIT_INVALID")
        self._replay_cache_limit = replay_cache_entries
        self._replay_cache_budget = replay_cache_bytes
        self._replay_cache = OrderedDict()
        self._replay_cache_size = 0
        self._replay_cache_lock = threading.Lock()

    def replay_cache_info(self):
        """Bounded process-local diagnostic counters; never an authority or persisted status."""
        with self._replay_cache_lock:
            return {"entries": len(self._replay_cache), "bytes": self._replay_cache_size}

    def cached_replay(self, key):
        """Reuse only a prior reconstructed result whose exact custody bytes still exist.

        Every hit reopens and SHA-verifies EVERY consumed object, including inputs/evaluator.
        No mtime/size shortcut. A changed/deleted object raises rather than falling back to a
        stale success. The stored entry remains a previous success, never a cached failure.
        """
        with self._replay_cache_lock:
            entry = self._replay_cache.get(key)
            if entry is None:
                return None
            self._replay_cache.move_to_end(key)
        references, serialized, _ = entry
        for reference in references:
            raw = self.get(reference)
            if digest(raw) != reference:
                raise ClosureError("EVIDENCE_HASH_MISMATCH")
        # The caller receives an independent result; mutations cannot poison later hits.
        return strict_loads(serialized)

    def remember_replay(self, key, references, result):
        """Called only after full successful reconstruction; nothing is loaded from disk."""
        serialized = canonical(result)
        references = tuple(sorted(set(references)))
        weight = (
            sys.getsizeof(key)
            + sum(sys.getsizeof(item) for item in key)
            + sys.getsizeof(references)
            + sum(sys.getsizeof(item) for item in references)
            + sys.getsizeof(serialized)
            + 256  # entry/LRU bookkeeping, conservatively counted
        )
        if not self._replay_cache_limit or weight > self._replay_cache_budget:
            return
        with self._replay_cache_lock:
            if key in self._replay_cache:
                self._replay_cache_size -= self._replay_cache.pop(key)[2]
            while self._replay_cache and (
                len(self._replay_cache) >= self._replay_cache_limit
                or self._replay_cache_size + weight > self._replay_cache_budget
            ):
                self._replay_cache_size -= self._replay_cache.popitem(last=False)[1][2]
            self._replay_cache[key] = (references, serialized, weight)
            self._replay_cache_size += weight

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
