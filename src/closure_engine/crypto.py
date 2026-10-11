"""Purpose-bound Ed25519 messages with externally supplied enrolled trust."""

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as SigningKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .protocol import ClosureError, canonical, digest, strict_loads, validate

PURPOSE_ROLES = {
    "approval": {"owner"},
    "risk-acceptance": {"owner"},
    "observation": {"verifier"},
    "ingestion": {"custodian"},
    "action-receipt": {"broker"},
    "run-binding": {"authority"},
    "closure-packet": {"authority"},
    "checkpoint": {"custodian"},
    "ledger-event": {"actor", "owner", "broker", "verifier", "authority", "custodian"},
}


@dataclass(frozen=True)
class Identity:
    role: str
    issuer: str
    private_key: SigningKey

    @property
    def key_id(self):
        return self.issuer + "-key-v1"

    @classmethod
    def generate(cls, role, issuer):
        return cls(role, issuer, SigningKey.generate())


@dataclass(frozen=True)
class TrustStore:
    raw: bytes

    @classmethod
    def from_identities(cls, identities, verifier_checks):
        records = [
            {
                "key_id": k.key_id,
                "issuer": k.issuer,
                "role": k.role,
                "public_key": k.private_key.public_key().public_bytes_raw().hex(),
                "checks": list(verifier_checks) if k.role == "verifier" else [],
            }
            for k in identities
        ]
        return cls.from_dict({"version": "v1", "keys": records})

    @classmethod
    def from_dict(cls, value):
        validate("trust-snapshot", value)
        if len({k["key_id"] for k in value["keys"]}) != len(value["keys"]):
            raise ClosureError("DUPLICATE_ENROLLMENT")
        if len({k["public_key"] for k in value["keys"]}) != len(value["keys"]) or (
            len({k["issuer"] for k in value["keys"]}) != len(value["keys"])
        ):
            raise ClosureError("IDENTITY_OR_KEY_REUSED_ACROSS_DOMAINS")
        return cls(canonical(value))

    @property
    def data(self):
        return strict_loads(self.raw)

    @property
    def hash(self):
        return digest(self.raw)

    def record(self, key_id):
        records = [r for r in self.data["keys"] if r["key_id"] == key_id]
        if len(records) != 1:
            raise ClosureError("UNENROLLED_KEY")
        return records[0]


def _message(purpose, payload):
    return ("ACE/v1/" + purpose + "\x00").encode() + canonical(payload)


def sign(identity, purpose, body, created_at):
    payload = {
        "version": "v1",
        "purpose": purpose,
        "issuer": identity.issuer,
        "key_id": identity.key_id,
        "created_at": created_at,
        "body": body,
    }
    envelope = {
        "algorithm": "Ed25519",
        "payload": payload,
        "signature": identity.private_key.sign(_message(purpose, payload)).hex(),
    }
    validate(purpose, envelope)
    return envelope


def verify(envelope, purpose, trust):
    validate(purpose, envelope)
    payload = envelope["payload"]
    record = trust.record(payload["key_id"])
    if record["issuer"] != payload["issuer"]:
        raise ClosureError("IDENTITY_MISMATCH")
    if record["role"] not in PURPOSE_ROLES[purpose]:
        raise ClosureError("SIGNING_PURPOSE_DENIED")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["public_key"])).verify(
            bytes.fromhex(envelope["signature"]), _message(purpose, payload)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ClosureError("SIGNATURE_INVALID") from exc
    return payload["body"]
