"""Encrypted cold snapshots for operator-owned ACE volumes, with independent ledger replay.

Live role services never mount this administrative tool's complete volume set. Stop them first.
The decryption key is a separate private file; keep it separately from the encrypted archive.
Restore accepts only empty destination roots and verifies retained evidence before installing.
"""

import hashlib
import io
import json
import os
import secrets
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..ledger import Ledger
from ..protocol import ClosureError, canonical, digest
from ..store import EvidenceStore
from .container_bootstrap import _ownership
from .deployment import Deployment
from .files import create_exclusive, read_json
from .identities import ROLES

MAGIC = b"ACE-BACKUP-V1\x00"
MAX_BYTES = 1_073_741_824
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


def verify_snapshot(root, expected_trust_hash):
    root = Path(root)
    deployment = Deployment(
        root,
        {
            **{role: root / "keys" / role for role in ROLES},
            "custodian": root / "custody-data",
            "operator": root / "operator",
        },
    )
    trust = deployment.load_trust(expected_trust_hash)
    for role in ROLES:
        deployment.identity(role, trust)
    custody = root / "custody-data"
    if not (custody / "ledger.sqlite").is_file():
        raise ClosureError("BACKUP_LEDGER_MISSING")
    checkpoint = read_json(custody / "checkpoint.json", "CHECKPOINT_MISSING")
    ledger = Ledger(custody / "ledger.sqlite", trust, EvidenceStore(custody / "evidence"), checkpoint)
    summary = ledger.summary(checkpoint)
    return {"trust_hash": trust.hash, "checkpoint_hash": digest(checkpoint), "ledger": summary}


class _EncryptedWriter(io.RawIOBase):
    def __init__(self, stream, cipher):
        self.stream, self.cipher = stream, cipher

    def writable(self):
        return True

    def write(self, value):
        self.stream.write(self.cipher.update(value))
        return len(value)


def backup(root, output, expected_trust_hash):
    root, output = Path(root), Path(output)
    verified = verify_snapshot(root, expected_trust_hash)
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    archive, key_file = output / "snapshot.ace", output / "snapshot.key"
    if archive.exists() or key_file.exists():
        raise ClosureError("BACKUP_ALREADY_EXISTS")
    files = []
    total = 0
    for relative in VOLUME_PATHS:
        folder = root / relative
        for path in sorted(folder.rglob("*")):
            if path.is_symlink():
                raise ClosureError("BACKUP_SYMLINK_DENIED")
            if path.is_file():
                size = path.stat().st_size
                total += size
                if total > MAX_BYTES:
                    raise ClosureError("BACKUP_TOO_LARGE")
                with path.open("rb") as stream:
                    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
                files.append({"path": path.relative_to(root).as_posix(), "size": size, "sha256": checksum})
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    create_exclusive(key_file, key, private=True)
    header = MAGIC + nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
    with archive.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    receipt = {
        "result": "Worked",
        "archive_sha256": checksum,
        "files": len(files),
        "source_bytes": total,
        "verification": verified,
        "key_file": str(key_file),
    }
    create_exclusive(output / "receipt.json", canonical(receipt) + b"\n")
    return receipt


def restore(root, archive, key_file, expected_trust_hash):
    root, archive = Path(root), Path(archive)
    for relative in VOLUME_PATHS:
        if any((root / relative).iterdir()) if (root / relative).exists() else False:
            raise ClosureError("RESTORE_TARGET_NOT_EMPTY", relative)
    if not len(MAGIC) + 28 < archive.stat().st_size <= MAX_BYTES:
        raise ClosureError("BACKUP_SIZE_INVALID")
    key = Path(key_file).read_bytes()
    if len(key) != 32:
        raise ClosureError("BACKUP_KEY_INVALID")
    with archive.open("rb") as source, tempfile.TemporaryFile() as compressed:
        header = source.read(len(MAGIC) + 12)
        if not header.startswith(MAGIC):
            raise ClosureError("BACKUP_FORMAT_INVALID")
        source.seek(-16, os.SEEK_END)
        tag = source.read(16)
        source.seek(len(header))
        cipher = Cipher(algorithms.AES(key), modes.GCM(header[-12:], tag)).decryptor()
        cipher.authenticate_additional_data(header)
        remaining = archive.stat().st_size - len(header) - 16
        while remaining:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise ClosureError("BACKUP_TRUNCATED")
            compressed.write(cipher.update(chunk))
            remaining -= len(chunk)
        compressed.write(cipher.finalize())  # Authentication must succeed before extraction.
        compressed.seek(0)
        with tempfile.TemporaryDirectory(prefix="ace-restore-") as temporary:
            stage = Path(temporary)
            manifest = None
            seen, total = set(), 0
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
                        manifest = json.loads(raw.read())
                        continue
                    if not any(entry.name.startswith(relative + "/") for relative in VOLUME_PATHS):
                        raise ClosureError("BACKUP_ENTRY_INVALID")
                    destination = stage / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("xb") as stream:
                        shutil.copyfileobj(raw, stream)
            if not isinstance(manifest, dict) or manifest.get("version") != "ace.backup.v1":
                raise ClosureError("BACKUP_MANIFEST_INVALID")
            if seen != {"manifest.json", *(item["path"] for item in manifest["files"])}:
                raise ClosureError("BACKUP_MANIFEST_MISMATCH")
            for item in manifest["files"]:
                path = stage / item["path"]
                with path.open("rb") as stream:
                    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
                if path.stat().st_size != item["size"] or checksum != item["sha256"]:
                    raise ClosureError("BACKUP_FILE_MISMATCH")
            verified = verify_snapshot(stage, expected_trust_hash)
            if verified != manifest["verification"]:
                raise ClosureError("BACKUP_REPLAY_MISMATCH")
            for item in manifest["files"]:
                destination = root / item["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                create_exclusive(destination, (stage / item["path"]).read_bytes(), private=True)
    owners = {
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
    for relative, uid in owners.items():
        if (root / relative).exists():
            _ownership(root / relative, uid)
    for path in (root / "operator").rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (root / "operator").chmod(0o755)
    (root / "keys/broker/intents").mkdir(mode=0o700, exist_ok=True)
    _ownership(root / "keys/broker/intents", 11005)
    return {"result": "Worked", "restored_files": len(manifest["files"]), "verification": verified}
