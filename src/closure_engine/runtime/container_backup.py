"""Encrypted cold snapshots for operator-owned ACE volumes, with independent ledger replay.

Live role services never mount this administrative tool's complete volume set. Stop them first.

Backup writes the archive into the output directory and the 32-byte decryption key to a
separate key file that must live outside that directory. A backup is reported Worked only
after the written archive bytes have been decrypted, checked file by file and replayed.

Restore decrypts and authenticates the whole archive, verifies every file and replays the
ledger against the operator pin, and refuses before installing anything unless the snapshot
contains an independently retained custodian checkpoint (no silent rollback, no fork).

Volumes are separate filesystems, so installation is NOT atomic across them. Instead a durable
RESTORE_STATE record (operator/RESTORE_STATE.json) is written before the first file is installed and
marked COMPLETE only after the last step. An interrupted restore can be resumed with the same
archive (byte-checked by digest): existing files must match the archive exactly and missing
files are installed. Services must not start unless restore_state() is None or COMPLETE.
"""

import hashlib
import io
import os
import secrets
import shutil
import tarfile
import tempfile
import zlib
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..crypto import TrustStore, verify
from ..ledger import Ledger
from ..protocol import ClosureError, canonical, digest, strict_loads
from ..store import EvidenceStore
from .container_bootstrap import _ownership
from .deployment import Deployment
from .files import create_exclusive, read_json, replace_json
from .identities import ROLES

MAGIC = b"ACE-BACKUP-V1\x00"
MAX_BYTES = 1_073_741_824
STATE_FILE = "RESTORE_STATE.json"
STATE_VOLUME = "operator"  # root bootstrap refuses operator/RESTORE_STATE.json unless COMPLETE
VOLUME_PATHS = (
    "keys/actor",
    "keys/owner",
    "keys/authority",
    "keys/verifier",
    "keys/broker",
    "operator",
    "auth/actor",
    "auth/owner",
    "auth/authority",
    "auth/verifier",
    "auth/broker",
    "custody-auth",
    "custody-data",
    "broker-intents",
    "gateway",
    "gateway-auth",
    "exports",
    "publisher-data",
)
OWNERS = {
    "keys/actor": 11001,
    "auth/actor": 11001,
    "keys/owner": 11002,
    "auth/owner": 11002,
    "keys/authority": 11003,
    "auth/authority": 11003,
    "keys/verifier": 11004,
    "auth/verifier": 11004,
    "keys/broker": 11005,
    "auth/broker": 11005,
    "broker-intents": 11005,
    "custody-data": 11006,
    "custody-auth": 11006,
    "gateway": 11007,
    "gateway-auth": 11007,
    "publisher-data": 11008,
}


def _deployment(root):
    root = Path(root)
    return Deployment(
        root,
        {
            **{role: root / "keys" / role for role in ROLES},
            "custodian": root / "custody-data",
            "operator": root / "operator",
        },
    )


def _ledger(root, trust, staged=False):
    custody = Path(root) / "custody-data"
    if not (custody / "ledger.sqlite").is_file():
        raise ClosureError("BACKUP_LEDGER_MISSING")
    checkpoint = read_json(custody / "checkpoint.json", "CHECKPOINT_MISSING")
    # Archives hold files only, so an empty evidence directory is recreated in private staging;
    # live source volumes are never written to (they are mounted read-only).
    store = EvidenceStore(custody / "evidence", create=staged)
    return Ledger(custody / "ledger.sqlite", trust, store, checkpoint), checkpoint


def verify_snapshot(root, expected_trust_hash, staged=False):
    deployment = _deployment(root)
    trust = deployment.load_trust(expected_trust_hash)
    for role in ROLES:
        deployment.identity(role, trust)
    ledger, checkpoint = _ledger(root, trust, staged)
    return {
        "trust_hash": trust.hash,
        "checkpoint_hash": digest(checkpoint),
        "ledger": ledger.summary(checkpoint),
    }


class _EncryptedWriter(io.RawIOBase):
    def __init__(self, stream, cipher):
        self.stream, self.cipher = stream, cipher

    def writable(self):
        return True

    def write(self, value):
        self.stream.write(self.cipher.update(value))
        return len(value)


def _file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _read_key(key_file):
    try:
        key = Path(key_file).read_bytes()
    except FileNotFoundError as exc:
        raise ClosureError("BACKUP_KEY_MISSING", str(key_file)) from exc
    if len(key) != 32:
        raise ClosureError("BACKUP_KEY_INVALID")
    return key


def _decrypt_and_stage(archive, key, stage):
    """Authenticate the whole archive, then extract it into ``stage`` and check every file."""
    archive = Path(archive)
    try:
        size = archive.stat().st_size
    except FileNotFoundError as exc:
        raise ClosureError("BACKUP_MISSING", str(archive)) from exc
    if not len(MAGIC) + 28 < size <= MAX_BYTES:
        raise ClosureError("BACKUP_SIZE_INVALID")
    with archive.open("rb") as source, tempfile.TemporaryFile() as compressed:
        header = source.read(len(MAGIC) + 12)
        if not header.startswith(MAGIC):
            raise ClosureError("BACKUP_FORMAT_INVALID", "not an ACE backup")
        source.seek(-16, os.SEEK_END)
        tag = source.read(16)
        source.seek(len(header))
        cipher = Cipher(algorithms.AES(key), modes.GCM(header[-12:], tag)).decryptor()
        cipher.authenticate_additional_data(header)
        remaining = size - len(header) - 16
        while remaining:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise ClosureError("BACKUP_TRUNCATED")
            compressed.write(cipher.update(chunk))
            remaining -= len(chunk)
        try:
            compressed.write(cipher.finalize())  # authentication succeeds before any extraction
        except InvalidTag as exc:
            raise ClosureError(
                "BACKUP_AUTHENTICATION_FAILED", "wrong key, tampered or truncated archive"
            ) from exc
        compressed.seek(0)
        manifest, seen, total = None, set(), 0
        try:
            with tarfile.open(fileobj=compressed, mode="r|gz") as tar:
                for entry in tar:
                    path = PurePosixPath(entry.name)
                    if not entry.isfile() or path.is_absolute() or ".." in path.parts or entry.name in seen:
                        raise ClosureError("BACKUP_ENTRY_INVALID")
                    seen.add(entry.name)
                    total += entry.size
                    if total > MAX_BYTES or len(seen) > 100000:
                        raise ClosureError("BACKUP_TOO_LARGE")
                    raw = tar.extractfile(entry)
                    if entry.name == "manifest.json":
                        if entry.size > 16_777_216:
                            raise ClosureError("BACKUP_MANIFEST_INVALID")
                        manifest = strict_loads(raw.read())  # duplicate keys refused (BK-08)
                        continue
                    if not any(entry.name.startswith(relative + "/") for relative in VOLUME_PATHS):
                        raise ClosureError("BACKUP_ENTRY_INVALID")
                    destination = stage / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("xb") as stream:
                        shutil.copyfileobj(raw, stream)
        except (tarfile.TarError, zlib.error, EOFError) as exc:
            raise ClosureError("BACKUP_FORMAT_INVALID", type(exc).__name__) from exc
    if not isinstance(manifest, dict) or manifest.get("version") != "ace.backup.v1":
        raise ClosureError("BACKUP_MANIFEST_INVALID")
    files = manifest.get("files")
    if not isinstance(files, list) or any(not isinstance(i, dict) or "path" not in i for i in files):
        raise ClosureError("BACKUP_MANIFEST_INVALID")
    if seen != {"manifest.json", *(item["path"] for item in files)}:
        raise ClosureError("BACKUP_MANIFEST_MISMATCH")
    for item in files:
        path = stage / item["path"]
        if path.stat().st_size != item["size"] or _file_sha256(path) != item["sha256"]:
            raise ClosureError("BACKUP_FILE_MISMATCH", item["path"])
    return manifest


def verify_archive(archive, key_file, expected_trust_hash):
    """Decrypt, authenticate, check every file and replay the ledger of an archive."""
    key = _read_key(key_file)
    with tempfile.TemporaryDirectory(prefix="ace-verify-") as temporary:
        stage = Path(temporary)
        manifest = _decrypt_and_stage(archive, key, stage)
        verified = verify_snapshot(stage, expected_trust_hash, staged=True)
        if verified != manifest["verification"]:
            raise ClosureError("BACKUP_REPLAY_MISMATCH")
        return {"files": len(manifest["files"]), "verification": verified}


def backup(root, output, expected_trust_hash, key_file):
    """Encrypted snapshot of the stopped volumes. The key file must be outside ``output``."""
    root, output, key_file = Path(root), Path(output), Path(key_file)
    resolved_output, resolved_key = output.resolve(), key_file.resolve()
    if resolved_key.parent == resolved_output or resolved_output in resolved_key.parents:
        raise ClosureError("BACKUP_KEY_BESIDE_ARCHIVE", "store the key file outside the archive directory")
    verified = verify_snapshot(root, expected_trust_hash)
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    archive = output / "snapshot.ace"
    if archive.exists() or key_file.exists():
        raise ClosureError("BACKUP_ALREADY_EXISTS")
    files, total = [], 0
    for relative in VOLUME_PATHS:
        for path in sorted((root / relative).rglob("*")):
            if path.is_symlink():
                raise ClosureError("BACKUP_SYMLINK_DENIED")
            if path.is_file():
                if relative == STATE_VOLUME and path.name == STATE_FILE and path.parent == root / relative:
                    continue  # restore bookkeeping is not deployment state
                size = path.stat().st_size
                total += size
                if total > MAX_BYTES:
                    raise ClosureError("BACKUP_TOO_LARGE")
                files.append(
                    {"path": path.relative_to(root).as_posix(), "size": size, "sha256": _file_sha256(path)}
                )
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    create_exclusive(key_file, key, private=True)
    header = MAGIC + nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(header)
        writer = _EncryptedWriter(stream, cipher)
        with tarfile.open(fileobj=writer, mode="w|gz") as tar:
            manifest = canonical({"version": "ace.backup.v1", "files": files, "verification": verified})
            entry = tarfile.TarInfo("manifest.json")
            entry.size = len(manifest)
            entry.mode = 0o600
            tar.addfile(entry, io.BytesIO(manifest))
            for item in files:
                tar.add(root / item["path"], arcname=item["path"], recursive=False)
        stream.write(cipher.finalize())
        stream.write(cipher.tag)
        stream.flush()
        os.fsync(stream.fileno())
    # BK-07: Worked only if the bytes actually written decrypt, match and replay.
    archived = verify_archive(archive, key_file, expected_trust_hash)
    if archived["verification"] != verified or archived["files"] != len(files):
        raise ClosureError("BACKUP_REPLAY_MISMATCH", "archived content differs from the verified source")
    receipt = {
        "result": "Worked",
        "archive_sha256": _file_sha256(archive),
        "files": len(files),
        "source_bytes": total,
        "verification": verified,
        "archive_verified": True,
        "key_file": str(key_file),
    }
    create_exclusive(output / "receipt.json", canonical(receipt) + b"\n")
    return receipt


def restore_state(root):
    """The durable restore record for this destination, or None if never restored into."""
    path = Path(root) / STATE_VOLUME / STATE_FILE
    return strict_loads(path.read_bytes()) if path.is_file() else None


def _occupied(root):
    """Files present in the destination volumes, excluding the restore record."""
    root, found = Path(root), []
    for relative in VOLUME_PATHS:
        folder = root / relative
        if folder.exists():
            for path in folder.rglob("*"):
                if path.is_file() and not (
                    relative == STATE_VOLUME and path.name == STATE_FILE and path.parent == folder
                ):
                    found.append(path.relative_to(root).as_posix())
    return sorted(found)


def _expected_checkpoint(value):
    if isinstance(value, dict):
        return value
    if value is None:
        raise ClosureError("EXPECTED_CHECKPOINT_REQUIRED")
    try:
        return strict_loads(Path(value).read_bytes())
    except FileNotFoundError as exc:
        raise ClosureError("EXPECTED_CHECKPOINT_MISSING", str(value)) from exc


def restore(root, archive, key_file, expected_trust_hash, expected_checkpoint, *, set_ownership=True):
    """Restore into empty volumes, or resume the same interrupted restore.

    ``expected_checkpoint`` is an independently retained custodian checkpoint (dict or file).
    The snapshot must contain that exact head at that sequence; an older snapshot or a forked
    history is refused before anything is installed. ``set_ownership`` applies container UIDs
    and modes (requires root); it exists only so non-root hosts can exercise the rest.
    """
    root, archive = Path(root), Path(archive)
    key = _read_key(key_file)
    anchor = _expected_checkpoint(expected_checkpoint)
    archive_sha256 = _file_sha256(archive)
    state = restore_state(root)
    occupied = _occupied(root)
    if state is not None:
        if state.get("archive_sha256") != archive_sha256:
            raise ClosureError("RESTORE_STATE_OTHER_ARCHIVE", "destination belongs to a different restore")
        if state.get("status") == "COMPLETE":
            return {
                "result": "AlreadyRestored",
                "restored_files": state["files"],
                "verification": state["verification"],
            }
    elif occupied:
        raise ClosureError("RESTORE_TARGET_NOT_EMPTY", occupied[0])
    with tempfile.TemporaryDirectory(prefix="ace-restore-") as temporary:
        stage = Path(temporary)
        manifest = _decrypt_and_stage(archive, key, stage)
        verified = verify_snapshot(stage, expected_trust_hash, staged=True)
        if verified != manifest["verification"]:
            raise ClosureError("BACKUP_REPLAY_MISMATCH")
        # BK-01: the independently retained head must be in the snapshot's history.
        trust = TrustStore.from_dict(strict_loads((stage / "operator" / "trust.json").read_bytes()))
        body = verify(anchor, "checkpoint", trust)
        if body["trust_hash"] != trust.hash:
            raise ClosureError("EXPECTED_CHECKPOINT_TRUST_MISMATCH")
        ledger, _ = _ledger(stage, trust, staged=True)
        try:
            ledger.verify(anchor)
        except ClosureError as exc:
            raise ClosureError(
                "SNAPSHOT_OLDER_THAN_EXPECTED_CHECKPOINT",
                f"snapshot lacks sequence {body['sequence']} head {body['head_hash']}",
            ) from exc
        names = [item["path"] for item in manifest["files"]]
        unexpected = sorted(set(occupied) - set(names))
        if unexpected:
            raise ClosureError("RESTORE_RESUME_CONFLICT", unexpected[0])
        record = {
            "version": "ace.restore-state.v1",
            "status": "INSTALLING",
            "archive_sha256": archive_sha256,
            "expected_checkpoint_hash": digest(anchor),
            "files": len(names),
            "verification": verified,
        }
        if state is None:
            # Durable record before the first file: an interruption is visible and resumable.
            create_exclusive(root / STATE_VOLUME / STATE_FILE, canonical(record) + b"\n", private=True)
        for item in manifest["files"]:
            destination = root / item["path"]
            if destination.exists():
                # Resume: an already installed file must be byte-identical to the archive.
                if destination.stat().st_size != item["size"] or _file_sha256(destination) != item["sha256"]:
                    raise ClosureError("RESTORE_RESUME_CONFLICT", item["path"])
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            create_exclusive(destination, (stage / item["path"]).read_bytes(), private=True)
    # Archives carry files only; recreate the custody evidence directory the source always had.
    (root / "custody-data" / "evidence").mkdir(parents=True, exist_ok=True)
    if set_ownership:
        for relative, uid in OWNERS.items():
            if (root / relative).exists():
                _ownership(root / relative, uid)
        for path in (root / "operator").rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        (root / "operator").chmod(0o755)
        (root / "keys/broker/intents").mkdir(mode=0o700, exist_ok=True)
        _ownership(root / "keys/broker/intents", 11005)
    replace_json(root / STATE_VOLUME / STATE_FILE, dict(record, status="COMPLETE"))
    return {"result": "Worked", "restored_files": len(names), "verification": verified}
