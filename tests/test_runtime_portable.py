"""Offline proofs exported from persistent keys, real deployment and live HTTP observations."""

import base64
import copy
import json
import subprocess
import sys
import threading

import pytest
from test_runtime_api import TOKENS, VIEWER, call
from test_runtime_e2e import CHECKS, artifact, free_port, run_to_verdict, world  # noqa: F401

from closure_engine.protocol import ClosureError, digest
from closure_engine.runtime import Runtime
from closure_engine.runtime.api import ApiServer
from closure_engine.runtime.portable import encode_bundle, read_bundle, verify_bundle


def test_runtime_bundle_includes_public_trust_policy_evidence_and_signed_history(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    assert run_to_verdict(runtime, "portable-control", artifact(2))[1]["verdict"] == "PROVEN"
    bundle = runtime.export_bundle("portable-control")
    assert "portable" in bundle
    assert bundle["portable"]["trust"]["keys"]
    assert bundle["portable"]["evaluators"]
    assert bundle["portable"]["evidence"]
    assert bundle["portable"]["pages"][-1]["checkpoint"]


@pytest.fixture(scope="module")
def proof_world(tmp_path_factory):
    """One actual accepted deployment; tests alter only copies of its exported proof."""
    from closure_engine.runtime import (
        ROLES,
        Deployment,
        ReferenceTarget,
        ReferenceTargetServer,
        enroll,
        enroll_target,
        init_identity,
    )

    root = tmp_path_factory.mktemp("portable-real")
    deployment = Deployment(root / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "portable-" + role)
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    target_port = free_port()
    info = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{target_port}", CHECKS)
    ReferenceTarget.initialize(root / "target", artifact(1), info["deploy_token_sha256"])
    server = ReferenceTargetServer(("127.0.0.1", target_port), root / "target")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    runtime = Runtime(deployment, pin)
    assert run_to_verdict(runtime, "portable-real", artifact(3))[1]["verdict"] == "PROVEN"
    assert runtime.accept("portable-real")["state"] == "ACCEPTED"
    bundle = runtime.export_bundle("portable-real")
    assert run_to_verdict(runtime, "portable-later", artifact(4))[1]["verdict"] == "PROVEN"
    assert runtime.accept("portable-later")["state"] == "ACCEPTED"
    (root / "later-public-proof.json").write_bytes(encode_bundle(runtime.export_bundle("portable-later")))
    # There is now physically no live target available for any offline verification below.
    server.shutdown()
    server.server_close()
    yield runtime, pin, bundle, root


def test_portable_acceptance_replays_existing_kernel_offline(proof_world):
    _, pin, bundle, _ = proof_world
    result = verify_bundle(bundle, pin)
    assert result["closure"]["verdict"] == "PROVEN"
    assert result["closure"]["state"] == "ACCEPTED"
    assert result["external_prior_checkpoint_checked"] is False
    frozen = bundle["portable"]["evaluators"][bundle["contract"]["evaluator_hash"]]
    assert frozen["criteria"]["primary"] == {"equals": 3, "restore_equals": 1}
    assert {key["role"] for key in bundle["portable"]["trust"]["keys"]} >= {
        "actor",
        "owner",
        "authority",
        "broker",
        "verifier",
        "custodian",
    }
    assert all(
        set(key) == {"key_id", "issuer", "role", "public_key", "checks"}
        for key in bundle["portable"]["trust"]["keys"]
    )


def test_public_proof_download_over_real_authenticated_api(proof_world):
    import hashlib

    runtime, pin, _, _ = proof_world
    credentials = {hashlib.sha256(token.encode()).hexdigest(): p for token, p in TOKENS.items()}
    server = ApiServer(("127.0.0.1", 0), runtime, credentials)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        path = "/api/v1/transactions/portable-real/bundle"
        assert call(port, "GET", path)[0] == 401
        status, downloaded = call(port, "GET", path, token=VIEWER)
        assert status == 200
        assert verify_bundle(downloaded, pin)["closure"]["state"] == "ACCEPTED"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "change",
    [
        "raw",
        "missing",
        "evaluator",
        "policy",
        "trust",
        "approval",
        "drop-event",
        "signature",
        "unsigned-outer-input",
    ],
)
def test_hostile_portable_material_refused_with_valid_control(proof_world, change):
    _, pin, original, _ = proof_world
    bundle = copy.deepcopy(original)
    proof = bundle["portable"]
    if change in {"raw", "missing"}:
        key = bundle["contract"]["evaluator_hash"]
        if change == "raw":
            proof["evidence"][key] = base64.b64encode(b"changed bytes").decode()
        else:
            del proof["evidence"][key]
    elif change == "evaluator":
        proof["evaluators"][bundle["contract"]["evaluator_hash"]]["criteria"]["primary"]["equals"] = 999
    elif change == "policy":
        proof["policies"][bundle["contract"]["policy_hash"]] = "always-pass"
    elif change == "trust":
        proof["trust"]["keys"][0]["public_key"] = "0" * 64
    elif change == "approval":
        proof["pages"][0]["contracts"][0]["contract"]["intent"] = "owner did not approve this"
    elif change == "drop-event":
        proof["pages"][-1]["events"].pop()
    elif change == "signature":
        proof["pages"][0]["events"][0]["signature"] = "0" * 128
    else:
        bundle["contract"]["intent"] = "different unsigned input"
    with pytest.raises(ClosureError):
        verify_bundle(bundle, pin)
    assert verify_bundle(original, pin)["closure"]["verdict"] == "PROVEN"


def test_self_asserted_keyring_is_not_a_trust_anchor(proof_world):
    _, _, bundle, _ = proof_world
    with pytest.raises(ClosureError, match="TRUST_ANCHOR_MISMATCH"):
        verify_bundle(bundle, "sha256:" + "0" * 64)
    with pytest.raises(ClosureError, match="INVALID_TRUST_ANCHOR"):
        verify_bundle(bundle, None)


def test_portable_cli_runs_without_runtime_target_or_private_keys(proof_world, tmp_path):
    _, pin, bundle, _ = proof_world
    path = tmp_path / "download.json"
    path.write_bytes(encode_bundle(bundle))
    checked = subprocess.run(
        [
            sys.executable,
            "-m",
            "closure_engine.runtime.portable",
            "--bundle",
            str(path),
            "--expected-trust-hash",
            pin,
            "--require-proven",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout)["closure"]["state"] == "ACCEPTED"
    missing_pin = subprocess.run(
        [sys.executable, "-m", "closure_engine.runtime.portable", "--bundle", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert missing_pin.returncode == 2
    assert "--expected-trust-hash" in missing_pin.stderr


def test_independently_retained_checkpoint_checked_and_signature_refused(proof_world):
    _, pin, bundle, _ = proof_world
    checkpoint = bundle["portable"]["pages"][-1]["checkpoint"]
    assert verify_bundle(bundle, pin, prior_checkpoint=checkpoint)["external_prior_checkpoint_checked"]
    bad = copy.deepcopy(checkpoint)
    bad["payload"]["body"]["sequence"] += 1
    with pytest.raises(ClosureError, match="SIGNATURE_INVALID"):
        verify_bundle(bundle, pin, prior_checkpoint=bad)


def test_real_later_anchor_refuses_older_signed_history_and_new_history_passes(proof_world):
    _, pin, older, root = proof_world
    later = read_bundle(root / "later-public-proof.json")
    prior = older["portable"]["pages"][-1]["checkpoint"]
    latest = later["portable"]["pages"][-1]["checkpoint"]
    assert latest["payload"]["body"]["sequence"] > prior["payload"]["body"]["sequence"]
    assert verify_bundle(later, pin, prior_checkpoint=prior)["closure"]["state"] == "ACCEPTED"
    with pytest.raises(ClosureError, match="CHECKPOINT_MISMATCH_OR_TRUNCATION"):
        verify_bundle(older, pin, prior_checkpoint=latest)


@pytest.mark.parametrize("field", ["transaction", "contract_hash", "artifact_hash"])
def test_valid_other_subject_not_substituted_for_caller_expected_subject(proof_world, field):
    _, pin, bundle, _ = proof_world
    expected = {"expected_" + field: "different" if field == "transaction" else "sha256:" + "0" * 64}
    with pytest.raises(ClosureError, match="PROOF_SUBJECT_MISMATCH"):
        verify_bundle(bundle, pin, **expected)
    assert (
        verify_bundle(
            bundle,
            pin,
            expected_transaction="portable-real",
            expected_contract_hash=digest(bundle["contract"]),
            expected_artifact_hash=bundle["binding"]["payload"]["body"]["artifact_hash"],
        )["closure"]["state"]
        == "ACCEPTED"
    )


def test_aggregate_container_over_one_mib_still_replays(proof_world, tmp_path):
    _, pin, original, _ = proof_world
    bundle = copy.deepcopy(original)
    # Real extra evidence bytes, not fake outcomes: their digest is verified too. The protocol
    # keeps each object <= 1 MiB while the portable download may legitimately contain many.
    raw = b"portable custody payload\n" * 23000
    bundle["portable"]["evidence"][digest(raw)] = base64.b64encode(raw).decode()
    raw2 = b"second portable custody payload\n" * 20000
    bundle["portable"]["evidence"][digest(raw2)] = base64.b64encode(raw2).decode()
    path = tmp_path / "larger-than-protocol-item.json"
    path.write_bytes(encode_bundle(bundle))
    assert path.stat().st_size > 1_048_576
    assert verify_bundle(read_bundle(path), pin)["closure"]["verdict"] == "PROVEN"


def test_duplicate_container_keys_refused(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"portable":{},"portable":{}}', encoding="utf-8")
    with pytest.raises(ClosureError, match="DUPLICATE_KEY"):
        read_bundle(path)
