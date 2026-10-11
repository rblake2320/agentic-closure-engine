"""Deployment layout, operator enrollment and enrolled target profiles.

Each role has its own state root so roles can later run under separate identities/containers.
The operator is the trusted administrative root: it enrolls public keys and targets, and hands
the resulting trust pin to every role out of band. Roles never read the pin from these folders.
"""

import hashlib
import hmac
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from ..crypto import TrustStore
from ..protocol import ClosureError, digest
from .files import create_exclusive, create_json, read_json
from .identities import ROLES, load_identity, load_public

TRUST_PIN = re.compile(r"^sha256:[0-9a-f]{64}$")
CHECK_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,160}$")
PROBES = {
    "primary": {"http-json"},
    "invariant": {"http-unchanged"},
    "deployment": {"active-artifact"},
    "stage": {"artifact-bytes"},
    "baseline": {"baseline-custody"},
}


def slug(identifier):
    """Filesystem-safe, collision-resistant name for protocol identifiers (which may contain '/')."""
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:32]


class Deployment:
    """Resolves role state roots. Default layout is <root>/<role>; each may be overridden."""

    def __init__(self, root, role_roots=None):
        self.root = Path(root)
        self.role_roots = {role: self.root / role for role in (*ROLES, "operator")}
        for role, path in (role_roots or {}).items():
            if role not in self.role_roots:
                raise ClosureError("UNKNOWN_ROLE", role)
            self.role_roots[role] = Path(path)

    def role_root(self, role):
        if role not in self.role_roots:
            raise ClosureError("UNKNOWN_ROLE", str(role))
        return self.role_roots[role]

    @property
    def trust_path(self):
        return self.role_root("operator") / "trust.json"

    def target_path(self, target_id):
        return self.role_root("operator") / "targets" / (slug(target_id) + ".json")

    def target_token_path(self, target_id):
        return self.role_root("broker") / "targets" / (slug(target_id) + ".token")

    def load_trust(self, expected_trust_hash):
        if not isinstance(expected_trust_hash, str) or not TRUST_PIN.fullmatch(expected_trust_hash):
            raise ClosureError("INVALID_TRUST_ANCHOR")
        trust = TrustStore.from_dict(read_json(self.trust_path, "ENROLLMENT_MISSING"))
        if not hmac.compare_digest(trust.hash, expected_trust_hash):
            raise ClosureError("TRUST_ANCHOR_MISMATCH")
        return trust

    def identity(self, role, trust):
        """Load a role key and require that it is the enrolled key for that role."""
        identity = load_identity(self.role_root(role), role)
        record = trust.record(identity.key_id)
        public = identity.private_key.public_key().public_bytes_raw().hex()
        if record["role"] != role or record["issuer"] != identity.issuer or record["public_key"] != public:
            raise ClosureError("IDENTITY_NOT_ENROLLED", role)
        return identity

    def target(self, target_id, trust_unused=None):
        profile = read_json(self.target_path(target_id), "TARGET_NOT_ENROLLED")
        if profile.get("target_id") != target_id:
            raise ClosureError("TARGET_PROFILE_MISMATCH", target_id)
        return profile


def enroll(deployment, verifier_checks):
    """Operator: build the enrollment snapshot from every role's public record. Never overwrites."""
    checks = list(verifier_checks)
    if not checks or any(not isinstance(c, str) or not CHECK_ID.fullmatch(c) for c in checks):
        raise ClosureError("INVALID_VERIFIER_CHECKS")
    if len(set(checks)) != len(checks):
        raise ClosureError("DUPLICATE_CHECK")
    if deployment.trust_path.exists():
        raise ClosureError("ENROLLMENT_ALREADY_EXISTS", str(deployment.trust_path))
    keys = []
    for role in ROLES:
        record = load_public(deployment.role_root(role))
        if record.get("role") != role:
            raise ClosureError("IDENTITY_ROLE_MISMATCH", role)
        keys.append({**record, "checks": sorted(checks) if role == "verifier" else []})
    trust = TrustStore.from_dict({"version": "v1", "keys": keys})
    create_exclusive(deployment.trust_path, trust.raw + b"\n")
    create_exclusive(deployment.role_root("operator") / "trust.pin", trust.hash.encode() + b"\n")
    return {"trust_hash": trust.hash, "trust_path": str(deployment.trust_path), "roles": list(ROLES)}


def _validate_base_url(value):
    if not isinstance(value, str):
        raise ClosureError("INVALID_TARGET_URL")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.path not in {"", "/"}:
        raise ClosureError("INVALID_TARGET_URL", value)
    if parts.query or parts.fragment or parts.username or parts.password:
        raise ClosureError("INVALID_TARGET_URL", value)
    return value.rstrip("/")


def enroll_target(deployment, target_id, base_url, checks, *, timeout_ms=5000):
    """Operator: enroll one HTTP target and its probe profile; issue the broker's deploy credential.

    ``checks`` is a list of {id, kind, phase, mandatory, probe}. The canonical profile digest
    becomes the contract evaluator_hash, so verifiers refuse any other probe definitions.
    Returns the credential hash the target must be configured with; the secret itself is only
    written to the broker's private state root.
    """
    if not isinstance(target_id, str) or not CHECK_ID.fullmatch(target_id):
        raise ClosureError("INVALID_TARGET_ID")
    if not isinstance(timeout_ms, int) or not 100 <= timeout_ms <= 60_000:
        raise ClosureError("INVALID_TARGET_TIMEOUT")
    normalized, seen = [], set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"id", "kind", "phase", "mandatory", "probe"}:
            raise ClosureError("INVALID_TARGET_CHECK")
        if not CHECK_ID.fullmatch(str(check["id"])) or check["id"] in seen:
            raise ClosureError("INVALID_TARGET_CHECK", str(check.get("id")))
        seen.add(check["id"])
        probe = check["probe"]
        if check["kind"] not in PROBES or not isinstance(probe, dict) or probe.get("type") not in PROBES[check["kind"]]:
            raise ClosureError("INVALID_TARGET_PROBE", check["id"])
        if check["phase"] not in {"instant", "window"} or not isinstance(check["mandatory"], bool):
            raise ClosureError("INVALID_TARGET_CHECK", check["id"])
        if probe["type"] in {"http-json", "http-unchanged"}:
            path = probe.get("path")
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("/ace/") or "?" in path:
                raise ClosureError("INVALID_TARGET_PROBE", check["id"])
        if probe["type"] == "http-json":
            pointers = (probe.get("pointer"), probe.get("artifact_pointer"))
            if set(probe) != {"type", "path", "pointer", "artifact_pointer"} or not all(
                isinstance(x, str) and x.startswith("/") for x in pointers
            ):
                raise ClosureError("INVALID_TARGET_PROBE", check["id"])
        elif probe["type"] == "http-unchanged":
            if set(probe) != {"type", "path"}:
                raise ClosureError("INVALID_TARGET_PROBE", check["id"])
        elif set(probe) != {"type"}:
            raise ClosureError("INVALID_TARGET_PROBE", check["id"])
        normalized.append(dict(check))
    token = secrets.token_urlsafe(32)
    profile = {
        "version": "v1",
        "target_id": target_id,
        "base_url": _validate_base_url(base_url),
        "timeout_ms": timeout_ms,
        "deploy_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "checks": normalized,
    }
    if deployment.target_path(target_id).exists():
        raise ClosureError("TARGET_ALREADY_ENROLLED", target_id)
    create_json(deployment.target_path(target_id), profile)
    create_exclusive(deployment.target_token_path(target_id), token.encode(), private=True)
    return {
        "target_id": target_id,
        "evaluator_hash": digest(profile),
        "deploy_token_sha256": profile["deploy_token_sha256"],
    }
