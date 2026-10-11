"""End-to-end operating runtime against a real HTTP target. No mocks: real keys on disk,
real loopback HTTP deployment and read-back, real ledger, custody and kernel verdicts."""

import json
import socket
import threading

import pytest

from closure_engine.protocol import ClosureError, digest
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
from closure_engine.runtime.target import TargetClient

CHECKS = [
    {
        "id": "primary",
        "kind": "primary",
        "phase": "instant",
        "mandatory": True,
        "probe": {
            "type": "http-json",
            "path": "/answer",
            "pointer": "/answer",
        },
    },
    {
        "id": "protected-config",
        "kind": "invariant",
        "phase": "window",
        "mandatory": True,
        "probe": {"type": "http-unchanged", "path": "/config"},
    },
    {
        "id": "protected-other",
        "kind": "invariant",
        "phase": "window",
        "mandatory": True,
        "probe": {"type": "http-unchanged", "path": "/other"},
    },
    {
        "id": "deployment",
        "kind": "deployment",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "active-artifact"},
    },
    {
        "id": "stage",
        "kind": "stage",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "artifact-bytes"},
    },
    {
        "id": "baseline",
        "kind": "baseline",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "baseline-custody"},
    },
]
WINDOW = {"duration_ms": 3000, "min_samples": 3, "max_clock_skew_ms": 1000, "settle_ms": 2500}


def artifact(answer, other="stable"):
    routes = {"/answer": {"answer": answer}, "/config": {"mode": "safe"}, "/other": {"value": other}}
    return json.dumps({"routes": routes}, sort_keys=True).encode()


def expect_of(raw):
    """The owner's desired value for the primary check: here, the answer the change should serve."""
    return {"primary": json.loads(raw)["routes"]["/answer"]["answer"]}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def world(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-prod")
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    port = free_port()
    target = enroll_target(deployment, "shop/api", "http://127.0.0.1:" + str(port), CHECKS)
    ReferenceTarget.initialize(tmp_path / "target", artifact(1), target["deploy_token_sha256"])
    server = ReferenceTargetServer(("127.0.0.1", port), tmp_path / "target")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield deployment, pin, tmp_path
    server.shutdown()
    server.server_close()


def run_to_verdict(runtime, tx, raw):
    runtime.propose(
        "shop/api",
        tx,
        raw,
        intent="Change the answer",
        expect=expect_of(raw),
        duration_ms=WINDOW["duration_ms"],
        min_samples=WINDOW["min_samples"],
        max_clock_skew_ms=WINDOW["max_clock_skew_ms"],
        settle_ms=WINDOW["settle_ms"],
    )
    runtime.approve(tx)
    runtime.freeze(tx)
    runtime.baseline(tx)
    runtime.bind(tx)
    deployed = runtime.deploy(tx)
    runtime.observe(tx, phase="all")
    first = runtime.close(tx)
    if first["state"] != "OBSERVING":
        return deployed, first
    return deployed, runtime.close(tx)


def test_valid_change_is_proven_accepted_and_independently_replayable(world):
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    deployed, result = run_to_verdict(runtime, "tx-valid", artifact(2))
    assert deployed["receipt"] == "EXECUTED"
    assert result["verdict"] == "PROVEN", result
    assert runtime.accept("tx-valid")["state"] == "ACCEPTED"
    # A fresh process view (restart) reopens the same ledger with the same persisted keys.
    again = Runtime(Deployment(deployment.root), pin)
    assert again.status("tx-valid")["state"] == "ACCEPTED"
    from closure_engine.verdicts import replay_packet

    meta = json.loads(
        (deployment.role_root("custodian") / "transactions").glob("*.json").__next__().read_bytes()
    )
    assert replay_packet(meta["verdict_packet"], again.store, again.trust)["verdict"] == "PROVEN"


def test_protected_state_damage_is_disproven_then_verified_recovery(world):
    deployment, pin, tmp = world
    runtime = Runtime(deployment, pin)
    _, result = run_to_verdict(runtime, "tx-bad", artifact(3, other="CHANGED"))
    assert result["verdict"] == "DISPROVEN"
    assert runtime.status("tx-bad")["state"] == "RECOVERY_REQUIRED"
    runtime.begin_recovery("tx-bad")
    _, child = run_to_verdict_child(runtime, "tx-bad/recovery")
    assert child["verdict"] == "PROVEN", child
    done = runtime.complete_recovery("tx-bad")
    assert done["state"] == "RECOVERED", done
    client = TargetClient(deployment.target("shop/api"))
    assert client.state()["artifact_hash"] == digest(artifact(1))


def run_to_verdict_child(runtime, tx):
    runtime.approve(tx)
    runtime.freeze(tx)
    runtime.baseline(tx)
    runtime.bind(tx)
    deployed = runtime.deploy(tx)
    runtime.observe(tx, phase="all")
    first = runtime.close(tx)
    if first["state"] != "OBSERVING":
        return deployed, first
    return deployed, runtime.close(tx)


def test_concurrent_change_blocks_deploy_without_side_effect(world):
    deployment, pin, tmp = world
    runtime = Runtime(deployment, pin)
    runtime.propose(
        "shop/api", "tx-race", artifact(4), intent="race", expect=expect_of(artifact(4)), **WINDOW
    )
    runtime.approve("tx-race")
    runtime.freeze("tx-race")
    runtime.baseline("tx-race")
    # Someone else legitimately deploys between baseline and our deployment.
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    other = TargetClient(deployment.target("shop/api"), token)
    assert other.deploy(artifact(9), digest(artifact(1)), "external-change")[0] == 200
    runtime.bind("tx-race")
    result = runtime.deploy("tx-race")
    assert result["receipt"] == "NOT_DEPLOYED"
    assert other.state()["artifact_hash"] == digest(artifact(9))  # newer state not clobbered


def test_crash_after_side_effect_reconciles_from_target_state(world):
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose(
        "shop/api", "tx-crash", artifact(5), intent="crash", expect=expect_of(artifact(5)), **WINDOW
    )
    runtime.approve("tx-crash")
    runtime.freeze("tx-crash")
    runtime.baseline("tx-crash")
    runtime.bind("tx-crash")
    intent = runtime.begin_intent("tx-crash")  # durable write-ahead record
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    client = TargetClient(deployment.target("shop/api"), token)
    # The side effect lands, then the broker process dies before writing any receipt.
    assert client.deploy(artifact(5), intent["expected_current"], intent["intent_id"])[0] == 200
    del runtime
    restarted = Runtime(Deployment(deployment.root), pin)
    assert restarted.status("tx-crash")["state"] == "EXECUTING"
    result = restarted.reconcile()
    assert result["reconciled"] == [
        {
            "intent_id": intent["intent_id"],
            "status": "COMPLETED",
            "receipt": "EXECUTED",
            "receipt_hash": result["reconciled"][0]["receipt_hash"],
        }
    ]
    assert restarted.status("tx-crash")["state"] == "VERIFYING"
    with pytest.raises(ClosureError, match="DEPLOYMENT_ALREADY_ATTEMPTED"):
        restarted.deploy("tx-crash")  # no blind second side effect


def test_unresolvable_target_state_is_quarantined_not_retried(world):
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose(
        "shop/api", "tx-q", artifact(6), intent="quarantine", expect=expect_of(artifact(6)), **WINDOW
    )
    for step in (runtime.approve, runtime.freeze, runtime.baseline, runtime.bind):
        step("tx-q")
    intent = runtime.begin_intent("tx-q")
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    client = TargetClient(deployment.target("shop/api"), token)
    # A third state appears (neither ours nor the precondition) before the broker reconciles.
    assert client.deploy(artifact(7), intent["expected_current"], "someone-else")[0] == 200
    resolved = runtime.reconcile_intent(intent["intent_id"])
    assert resolved["status"] == "QUARANTINED" and resolved["receipt"] == "UNKNOWN"
    assert runtime.status("tx-q")["state"] == "EXECUTING"
    assert client.state()["artifact_hash"] == digest(artifact(7))
