"""Persistent per-role Ed25519 identities.

Each role owns one state root. The private key is created once with exclusive, owner-only
creation and is never printed or overwritten. Set ACE_KEY_PASSPHRASE to encrypt keys at rest.
"""

import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import Identity
from ..protocol import ClosureError
from .files import create_exclusive, create_json, read_json

ROLES = ("actor", "owner", "broker", "verifier", "authority", "custodian")
ISSUER = re.compile(r"^[A-Za-z0-9._:/-]{1,150}$")
KEY_FILE = "identity.key"
PUBLIC_FILE = "identity.json"


def _passphrase():
    value = os.environ.get("ACE_KEY_PASSPHRASE")
    return value.encode("utf-8") if value else None


def public_record(identity):
    return {
        "role": identity.role,
        "issuer": identity.issuer,
        "key_id": identity.key_id,
        "public_key": identity.private_key.public_key().public_bytes_raw().hex(),
    }


def init_identity(role_root, role, issuer):
    """Create a role identity once. Returns only the public record."""
    if role not in ROLES:
        raise ClosureError("UNKNOWN_ROLE", str(role))
    if not isinstance(issuer, str) or not ISSUER.fullmatch(issuer):
        raise ClosureError("INVALID_ISSUER")
    root = Path(role_root)
    if (root / KEY_FILE).exists() or (root / PUBLIC_FILE).exists():
        raise ClosureError("IDENTITY_ALREADY_EXISTS", str(root))
    key = Ed25519PrivateKey.generate()
    secret = _passphrase()
    encryption = serialization.BestAvailableEncryption(secret) if secret else serialization.NoEncryption()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    identity = Identity(role, issuer, key)
    create_exclusive(root / KEY_FILE, pem, private=True)
    record = public_record(identity)
    create_json(root / PUBLIC_FILE, record)
    return record


def load_identity(role_root, role):
    """Load a persisted identity and check it still matches its public record."""
    root = Path(role_root)
    record = read_json(root / PUBLIC_FILE, "IDENTITY_MISSING")
    try:
        pem = (root / KEY_FILE).read_bytes()
    except FileNotFoundError as exc:
        raise ClosureError("PRIVATE_KEY_MISSING", str(root)) from exc
    try:
        key = serialization.load_pem_private_key(pem, password=_passphrase())
    except (TypeError, ValueError) as exc:
        raise ClosureError("PRIVATE_KEY_UNREADABLE", str(root)) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ClosureError("PRIVATE_KEY_UNREADABLE", str(root))
    if record.get("role") != role:
        raise ClosureError("IDENTITY_ROLE_MISMATCH", str(root))
    identity = Identity(role, record["issuer"], key)
    if public_record(identity) != record:
        raise ClosureError("IDENTITY_TAMPERED", str(root))
    return identity


def load_public(role_root):
    return read_json(Path(role_root) / PUBLIC_FILE, "IDENTITY_MISSING")
