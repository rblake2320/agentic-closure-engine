"""Real TLS witness process and public-only independent offline temporal proof replay."""

import copy
import hashlib
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from test_runtime_api import call
from test_runtime_e2e import CHECKS, artifact, free_port, run_to_verdict, run_to_verdict_child, world  # noqa: F401
from test_witness_gate import tls  # noqa: F401

from closure_engine.protocol import ClosureError, canonical, digest
from closure_engine.runtime import (
    ROLES,
    Deployment,
    ReferenceTarget,
    ReferenceTargetServer,
    Runtime,
    enroll,
    enroll_target,
    init_identity,
)
from closure_engine.runtime.api import ApiServer
from closure_engine.runtime.custody_service import CustodyServer, RemoteCustody
from closure_engine.runtime.files import create_json
from closure_engine.runtime.portable import encode_bundle, verify_bundle
from closure_engine.time_assurance import verify_time_assurance
from closure_engine.time_witness import initialize


@pytest.fixture(scope="module")
def public_world(tmp_path_factory, tls):  # noqa: F811
    root = tmp_path_factory.mktemp("time-assurance-real")
    deployment = Deployment(root / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "public-time-" + role)
    pin = enroll(deployment, [check["id"] for check in CHECKS])["trust_hash"]
    port = free_port()
    profile = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{port}", CHECKS)
    ReferenceTarget.initialize(root / "target", artifact(1), profile["deploy_token_sha256"])
    target = ReferenceTargetServer(("127.0.0.1", port), root / "target")
    threading.Thread(target=target.serve_forever, daemon=True).start()
    runtime = Runtime(deployment, pin)
    witness_root = root / "independent-time"
    enrolled = initialize(witness_root, "public-tls-witness", runtime.trust, pin, max_receipt_age_ms=5000)
    command, env = [sys.executable], dict(os.environ)
    if os.environ.get("TIME_WITNESS_INSTALLED") == "1":
        command.append("-I")
    else:
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    command.extend(
        [
            "-m",
            "closure_engine.time_witness",
            "serve",
            "--root",
            str(witness_root),
            "--expected-witness-hash",
            enrolled["expected_witness_hash"],
            "--expected-authority-hash",
            pin,
            "--port",
            "0",
            "--tls-cert",
            str(tls / "server.pem"),
            "--tls-key",
            str(tls / "server.key"),
        ]
    )
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    output = queue.Queue()
    threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True).start()
    try:
        message = json.loads(output.get(timeout=15))
        assert message["status"] == "LISTENING"
        config = {
            "version": "v1",
            "endpoint": "https://127.0.0.1:" + str(message["port"]),
            "manifest": enrolled["manifest"],
            "expected_witness_hash": enrolled["expected_witness_hash"],
            "expected_authority_hash": pin,
            "token_file": str((witness_root / "client.token").resolve()),
            "ca_file": str((tls / "ca.pem").resolve()),
            "timeout_ms": 5000,
        }
        create_json(deployment.role_root("operator") / "witness-gate.json", config)
        runtime = Runtime(deployment, pin)
        assert run_to_verdict(runtime, "public-wrapped", artifact(2))[1]["verdict"] == "PROVEN"
        assert runtime.accept("public-wrapped")["state"] == "ACCEPTED"
        assert run_to_verdict(runtime, "foreign-private", artifact(4))[1]["verdict"] == "PROVEN"
        assert runtime.accept("foreign-private")["state"] == "ACCEPTED"
        wrapper = runtime.time_assurance("public-wrapped")
        kwargs = {
            "expected_authority_hash": pin,
            "expected_witness_hash": enrolled["expected_witness_hash"],
            "expected_transaction": "public-wrapped",
            "expected_contract_hash": wrapper["portable_bundle"]["contract"]
            and digest(wrapper["portable_bundle"]["contract"]),
            "expected_artifact_hash": digest(artifact(2)),
        }
        yield runtime, wrapper, kwargs, root, {"witness": process, "target": target}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        target.shutdown()
        target.server_close()


def test_public_replay_keeps_v2_and_native_truth_separate_from_historical_clock(public_world):
    _, wrapper, kwargs, _, _ = public_world
    original = encode_bundle(wrapper["portable_bundle"])
    from closure_engine.protocol import milliseconds

    oldest = min(milliseconds(record["receipt"]["body"]["received_at"]) for record in wrapper["sidecars"])
    assert time.time_ns() // 1_000_000 - oldest > wrapper["sidecars"][0]["manifest"]["max_receipt_age_ms"]
    result = verify_time_assurance(wrapper, **kwargs)
    assert result["technical"]["verdict"] == "PROVEN"
    assert result["technical"]["state"] == "ACCEPTED"
    assert result["time_assurance"]["status"] == "HISTORICAL_WITNESSED"
    assert result["time_assurance"]["current_target_state"] == "NOT_OBSERVED"
    assert wrapper["portable_bundle"]["portable"]["version"] == "ace.portable.v2"
    assert encode_bundle(wrapper["portable_bundle"]) == original
    assert (
        verify_bundle(wrapper["portable_bundle"], kwargs["expected_authority_hash"])["closure"]
        == result["technical"]
    )
    assert {record["event"]["payload"]["body"]["transaction_id"] for record in wrapper["sidecars"]} == {
        "public-wrapped"
    }
    assert len(wrapper["sidecars"]) == 2  # authority PROVEN event and owner acceptance closure receipt
    raw = encode_bundle(wrapper)
    for forbidden in (b"token_file", b"ca_file", b"identity.key", b"BEGIN PRIVATE KEY"):
        assert forbidden not in raw


@pytest.mark.parametrize(
    "attack",
    [
        "pin-a",
        "pin-b",
        "transaction",
        "contract",
        "artifact",
        "receipt-signature",
        "consumption-signature",
        "missing",
        "duplicate",
        "subject",
        "config",
        "manifest-key",
        "foreign-event",
    ],
)
def test_independent_pins_bindings_and_temporal_receipt_tampering_refused(public_world, attack):
    runtime, original, kwargs, _, _ = public_world
    wrapper, expected = copy.deepcopy(original), dict(kwargs)
    record = wrapper["sidecars"][0]
    if attack in {"pin-a", "pin-b"}:
        expected["expected_authority_hash" if attack == "pin-a" else "expected_witness_hash"] = digest(
            b"wrong-root"
        )
    elif attack in {"transaction", "contract", "artifact"}:
        expected[
            "expected_"
            + {"transaction": "transaction", "contract": "contract_hash", "artifact": "artifact_hash"}[attack]
        ] = "another-transaction" if attack == "transaction" else digest(b"wrong-subject")
    elif attack == "receipt-signature":
        record["receipt"]["signature"] = "00" * 64
    elif attack == "consumption-signature":
        record["consumption"]["signature"] = "00" * 64
    elif attack == "missing":
        wrapper["sidecars"].pop()
    elif attack == "duplicate":
        wrapper["sidecars"][1] = copy.deepcopy(record)
    elif attack == "subject":
        record["subject"] = wrapper["sidecars"][1]["subject"]
    elif attack == "config":
        record["config_hash"] = digest(b"unapproved-policy")
    elif attack == "manifest-key":
        record["manifest"]["public_key"] = secrets.token_hex(32)
    else:
        foreign = next(
            event
            for event in runtime.audit_export()["events"]
            if event["payload"]["body"]["transaction_id"] == "foreign-private"
            and event["payload"]["body"]["state"] == "PROVEN"
        )
        wrapper["sidecars"][0] = runtime.custody.witness_record(digest(foreign))
    with pytest.raises(ClosureError):
        verify_time_assurance(wrapper, **expected)


def test_authenticated_api_and_remote_custody_export_actual_public_receipts(public_world):
    runtime, _, kwargs, _, _ = public_world
    token = secrets.token_hex(32)
    credentials = {
        hashlib.sha256(token.encode()).hexdigest(): {"principal": "time-viewer", "roles": ["viewer"]}
    }
    server = ApiServer(("127.0.0.1", 0), runtime, credentials)
    custody_server = CustodyServer(("127.0.0.1", 0), runtime.custody, hosts=None, credentials=credentials)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=custody_server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        assert call(port, "GET", "/api/v1/transactions/public-wrapped/time-assurance")[0] == 401
        status, wrapper = call(port, "GET", "/api/v1/transactions/public-wrapped/time-assurance", token=token)
        assert status == 200
        assert verify_time_assurance(wrapper, **kwargs)["time_assurance"]["status"] == "HISTORICAL_WITNESSED"
        remote = RemoteCustody("http://127.0.0.1:" + str(custody_server.server_address[1]), token)
        assert remote.witness_record(digest(wrapper["sidecars"][0]["event"])) == wrapper["sidecars"][0]
    finally:
        server.shutdown()
        server.server_close()
        custody_server.shutdown()
        custody_server.server_close()


def test_recovered_parent_requires_parent_child_and_recovery_outcome_witnesses(public_world):
    runtime, _, kwargs, _, _ = public_world
    assert (
        run_to_verdict(runtime, "public-recovery", artifact(6, other="damaged"))[1]["verdict"] == "DISPROVEN"
    )
    runtime.begin_recovery("public-recovery")
    assert run_to_verdict_child(runtime, "public-recovery/recovery")[1]["verdict"] == "PROVEN"
    assert runtime.complete_recovery("public-recovery")["state"] == "RECOVERED"
    wrapper = runtime.time_assurance("public-recovery")
    expected = dict(
        kwargs,
        expected_transaction="public-recovery",
        expected_contract_hash=digest(runtime._tx("public-recovery")["contract"]),
        expected_artifact_hash=digest(artifact(6, other="damaged")),
    )
    result = verify_time_assurance(wrapper, **expected)
    assert result["technical"]["verdict"] == "DISPROVEN"
    assert result["technical"]["state"] == "RECOVERED"
    assert result["time_assurance"]["status"] == "HISTORICAL_WITNESSED"
    assert {record["event"]["payload"]["body"]["state"] for record in wrapper["sidecars"]} == {
        "DISPROVEN",
        "PROVEN",
        "RECOVERED",
    }
    for index in range(3):
        missing = copy.deepcopy(wrapper)
        missing["sidecars"].pop(index)
        with pytest.raises(ClosureError, match="TIME_ASSURANCE_REQUIRED_RECEIPT_MISSING"):
            verify_time_assurance(missing, **expected)


def test_normal_mode_without_witness_retains_technical_proof_but_time_assurance_unavailable(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    assert run_to_verdict(runtime, "no-time-profile", artifact(2))[1]["verdict"] == "PROVEN"
    assert runtime.accept("no-time-profile")["state"] == "ACCEPTED"
    packet = canonical(runtime.closure("no-time-profile"))
    with pytest.raises(ClosureError, match="TIME_ASSURANCE_UNAVAILABLE"):
        runtime.time_assurance("no-time-profile")
    assert canonical(runtime.closure("no-time-profile")) == packet
    assert verify_bundle(runtime.export_bundle("no-time-profile"), pin)["closure"]["verdict"] == "PROVEN"


def test_fresh_offline_process_has_only_public_inputs_and_both_pins(public_world):
    _, wrapper, kwargs, root, handles = public_world
    handles["witness"].kill()
    handles["witness"].wait(timeout=5)
    handles["target"].shutdown()
    handles["target"].server_close()
    folder = root / "offline-public"
    folder.mkdir()
    proof_file = folder / "proof.json"
    proof_file.write_bytes(encode_bundle(wrapper))
    # No target/service URLs or credentials are passed; verification takes no network dependency.
    command, env = [sys.executable], dict(os.environ)
    if os.environ.get("TIME_WITNESS_INSTALLED") == "1":
        command.append("-I")
    else:
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    command.extend(["-m", "closure_engine.time_assurance", "--proof", str(proof_file)])
    for name, value in kwargs.items():
        command.extend(["--" + name.replace("_", "-"), value])
    completed = subprocess.run(command, cwd=folder, env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["technical"]["verdict"] == "PROVEN"
    assert result["time_assurance"]["status"] == "HISTORICAL_WITNESSED"
    assert list(folder.iterdir()) == [proof_file]
