"""Persistent identities, enrollment pin and target enrollment fail closed."""

import pytest

from closure_engine.protocol import ClosureError
from closure_engine.runtime import (
    ROLES,
    Deployment,
    Runtime,
    enroll,
    enroll_target,
    init_identity,
    load_identity,
)

CHECKS = ["primary"]
PROBE_CHECKS = [
    {
        "id": "primary",
        "kind": "primary",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "http-json", "path": "/a", "pointer": "/a", "artifact_pointer": "/a"},
    }
]


def all_roles(deployment):
    return {role: init_identity(deployment.role_root(role), role, role + "-1") for role in ROLES}


def test_identity_persists_and_is_never_regenerated(tmp_path):
    root = tmp_path / "owner"
    public = init_identity(root, "owner", "owner-1")
    assert "private" not in str(public).lower() and set(public) == {"role", "issuer", "key_id", "public_key"}
    first = load_identity(root, "owner").private_key.public_key().public_bytes_raw().hex()
    second = load_identity(root, "owner").private_key.public_key().public_bytes_raw().hex()
    assert first == second == public["public_key"]
    with pytest.raises(ClosureError, match="IDENTITY_ALREADY_EXISTS"):
        init_identity(root, "owner", "owner-1")
    assert load_identity(root, "owner").private_key.public_key().public_bytes_raw().hex() == first


def test_missing_or_tampered_identity_fails_closed(tmp_path):
    root = tmp_path / "broker"
    init_identity(root, "broker", "broker-1")
    record = (root / "identity.json").read_bytes()
    (root / "identity.json").write_bytes(record.replace(b'"broker-1"', b'"broker-2"'))
    with pytest.raises(ClosureError, match="IDENTITY_TAMPERED"):
        load_identity(root, "broker")
    (root / "identity.json").write_bytes(record)
    with pytest.raises(ClosureError, match="IDENTITY_ROLE_MISMATCH"):
        load_identity(root, "owner")
    (root / "identity.key").unlink()
    with pytest.raises(ClosureError, match="PRIVATE_KEY_MISSING"):
        load_identity(root, "broker")


def test_passphrase_encrypts_key_at_rest(tmp_path, monkeypatch):
    monkeypatch.setenv("ACE_KEY_PASSPHRASE", "correct horse battery staple")
    init_identity(tmp_path / "authority", "authority", "authority-1")
    assert b"ENCRYPTED" in (tmp_path / "authority" / "identity.key").read_bytes()
    load_identity(tmp_path / "authority", "authority")
    monkeypatch.setenv("ACE_KEY_PASSPHRASE", "wrong")
    with pytest.raises(ClosureError, match="PRIVATE_KEY_UNREADABLE"):
        load_identity(tmp_path / "authority", "authority")
    monkeypatch.delenv("ACE_KEY_PASSPHRASE")
    with pytest.raises(ClosureError, match="PRIVATE_KEY_UNREADABLE"):
        load_identity(tmp_path / "authority", "authority")


def test_enrollment_requires_every_role_and_never_overwrites(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    init_identity(deployment.role_root("owner"), "owner", "owner-1")
    with pytest.raises(ClosureError, match="IDENTITY_MISSING"):
        enroll(deployment, CHECKS)
    for role in ROLES:
        if role != "owner":
            init_identity(deployment.role_root(role), role, role + "-1")
    pin = enroll(deployment, CHECKS)["trust_hash"]
    with pytest.raises(ClosureError, match="ENROLLMENT_ALREADY_EXISTS"):
        enroll(deployment, CHECKS)
    assert Runtime(deployment, pin).trust.hash == pin


def test_runtime_requires_the_independent_pin(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    all_roles(deployment)
    pin = enroll(deployment, CHECKS)["trust_hash"]
    with pytest.raises(ClosureError, match="TRUST_ANCHOR_MISMATCH"):
        Runtime(deployment, "sha256:" + "0" * 64)
    with pytest.raises(ClosureError, match="INVALID_TRUST_ANCHOR"):
        Runtime(deployment, "trust-me")
    raw = deployment.trust_path.read_bytes()
    deployment.trust_path.write_bytes(raw.replace(b"owner-1", b"owner-9"))
    with pytest.raises(ClosureError):
        Runtime(deployment, pin)  # tampered enrollment no longer matches the pin


def test_replaced_role_key_is_not_enrolled(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    all_roles(deployment)
    pin = enroll(deployment, CHECKS)["trust_hash"]
    runtime = Runtime(deployment, pin)
    for name in ("identity.key", "identity.json"):
        (deployment.role_root("broker") / name).unlink()
    init_identity(deployment.role_root("broker"), "broker", "broker-1")  # same name, new key
    with pytest.raises(ClosureError, match="IDENTITY_NOT_ENROLLED"):
        runtime._identity("broker")


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1:1",
        "http://127.0.0.1:1/path",
        "http://user:pw@127.0.0.1:1",
        "http://127.0.0.1:1?x=1",
        "nohost",
    ],
)
def test_target_url_must_be_a_plain_origin(tmp_path, url):
    with pytest.raises(ClosureError, match="INVALID_TARGET_URL"):
        enroll_target(Deployment(tmp_path / "ace"), "t1", url, PROBE_CHECKS)


def test_target_enrollment_keeps_secret_private_and_rejects_bad_probes(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    result = enroll_target(deployment, "t1", "http://127.0.0.1:8000", PROBE_CHECKS)
    token = deployment.target_token_path("t1").read_bytes()
    assert token and token not in deployment.target_path("t1").read_bytes()
    assert token.decode() not in str(result)
    with pytest.raises(ClosureError, match="TARGET_ALREADY_ENROLLED"):
        enroll_target(deployment, "t1", "http://127.0.0.1:8000", PROBE_CHECKS)
    bad = [dict(PROBE_CHECKS[0], probe={"type": "shell", "command": "rm -rf /"})]
    with pytest.raises(ClosureError, match="INVALID_TARGET_PROBE"):
        enroll_target(deployment, "t2", "http://127.0.0.1:8000", bad)
    escape = [dict(PROBE_CHECKS[0], probe=dict(PROBE_CHECKS[0]["probe"], path="/ace/v1/artifact"))]
    with pytest.raises(ClosureError, match="INVALID_TARGET_PROBE"):
        enroll_target(deployment, "t3", "http://127.0.0.1:8000", escape)
