"""F2: two real target deployments must not disclose each other's artifact bytes."""

import base64
import copy
import json
import threading

import pytest
from test_independent_boundary_review import _fail_sample
from test_ledger import begin, event, packet
from test_runtime_e2e import CHECKS, WINDOW, free_port

from closure_engine.crypto import sign
from closure_engine.protocol import ClosureError, digest, timestamp
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
from closure_engine.runtime.portable import verify_bundle

CANARY_B = "PRIVATE-ARTIFACT-B-4f0d6f7911fc4c90a9"


def private_artifact(answer, marker, reference=None):
    routes = {
        "/answer": {"answer": answer},
        "/config": {"mode": "safe"},
        "/other": {"value": "stable"},
        "/private": {"marker": marker},
    }
    if reference:
        routes["/reference"] = {"digest": reference}
    return json.dumps({"routes": routes}, sort_keys=True).encode()


@pytest.fixture(scope="module")
def two_targets(tmp_path_factory):
    root = tmp_path_factory.mktemp("portable-f2-real")
    deployment = Deployment(root / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "f2-" + role)
    pin = enroll(deployment, [check["id"] for check in CHECKS])["trust_hash"]
    servers = []
    raw_b = private_artifact(5, CANARY_B)
    raw_a = private_artifact(3, "PRIVATE-ARTIFACT-A", digest(raw_b))
    for target_id in ("tenant-a", "tenant-b"):
        port = free_port()
        info = enroll_target(deployment, target_id, f"http://127.0.0.1:{port}", CHECKS)
        state = root / target_id
        ReferenceTarget.initialize(
            state, private_artifact(1, target_id + "-baseline"), info["deploy_token_sha256"]
        )
        server = ReferenceTargetServer(("127.0.0.1", port), state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    runtime = Runtime(deployment, pin)
    for target_id, transaction, raw, expect in (
        ("tenant-a", "tenant-a-change", raw_a, 3),
        ("tenant-b", "tenant-b-change", raw_b, 5),
    ):
        runtime.propose(
            target_id,
            transaction,
            raw,
            intent="Actual per-target artifact change",
            expect={"primary": expect},
            **WINDOW,
        )
        runtime.approve(transaction)
        runtime.freeze(transaction)
        runtime.baseline(transaction)
        result = runtime.run(transaction)
        assert result["verdict"] == "PROVEN", result
        assert runtime.accept(transaction)["state"] == "ACCEPTED"
    bundle = runtime.export_bundle("tenant-a-change")
    runtime.propose(
        "tenant-a",
        "tenant-a-failure",
        private_artifact(9, "PRIVATE-A-WRONG"),
        intent="Actual wrong result to verify restoration",
        expect={"primary": 7},
        **WINDOW,
    )
    for action in ("approve", "freeze", "baseline"):
        getattr(runtime, action)("tenant-a-failure")
    assert runtime.run("tenant-a-failure")["verdict"] == "DISPROVEN"
    child = runtime.begin_recovery("tenant-a-failure")["transaction_id"]
    for action in ("approve", "freeze", "baseline"):
        getattr(runtime, action)(child)
    assert runtime.run(child)["verdict"] == "PROVEN"
    assert runtime.complete_recovery("tenant-a-failure")["state"] == "RECOVERED"
    from closure_engine.runtime.portable import encode_bundle

    (root / "recovered-proof.json").write_bytes(encode_bundle(runtime.export_bundle("tenant-a-failure")))
    (root / "child-proof.json").write_bytes(encode_bundle(runtime.export_bundle(child)))
    for server in servers:
        server.shutdown()
        server.server_close()
    yield runtime, pin, bundle, raw_a, raw_b, root


def test_F2_other_target_artifact_canary_never_in_requested_bundle(two_targets):
    _, pin, bundle, raw_a, raw_b, _ = two_targets
    evidence = bundle["portable"]["evidence"]
    decoded = [base64.b64decode(item) for item in evidence.values()]
    assert raw_a in decoded
    assert raw_b not in decoded
    assert digest(raw_b) not in evidence
    assert not any(CANARY_B.encode() in item for item in decoded)
    assert verify_bundle(bundle, pin)["closure"]["state"] == "ACCEPTED"


def test_scoped_proof_declares_foreign_semantics_not_evaluated(two_targets):
    _, pin, bundle, _, _, _ = two_targets
    result = verify_bundle(bundle, pin)
    assert result["verification_scope"] == {
        "mode": "transaction",
        "transactions": ["tenant-a-change"],
        "global_chain": "SIGNATURES_HASH_LINKS_CHRONOLOGY_CHECKPOINT",
        "foreign_transaction_semantics": "NOT_EVALUATED",
    }
    assert set(result["transactions"]) == {"tenant-a-change"}
    contracts = bundle["portable"]["pages"][0]["contracts"]
    assert [item["contract"]["transaction_id"] for item in contracts] == ["tenant-a-change"]
    # This is artifact minimization, not concealment of shared global event metadata.
    assert any(
        event["payload"]["body"]["transaction_id"] == "tenant-b-change"
        for page in bundle["portable"]["pages"]
        for event in page["events"]
    )


def test_real_recovery_scope_preserves_parent_child_checks_without_foreign_artifacts(two_targets):
    from closure_engine.runtime.portable import read_bundle

    _, pin, _, _, raw_b, root = two_targets
    parent = read_bundle(root / "recovered-proof.json")
    child = read_bundle(root / "child-proof.json")
    for proof in (parent, child):
        assert digest(raw_b) not in proof["portable"]["evidence"]
        assert not any(
            CANARY_B.encode() in base64.b64decode(raw) for raw in proof["portable"]["evidence"].values()
        )
        assert len(proof["portable"]["scope"]["transactions"]) == 2
    result = verify_bundle(parent, pin)
    assert result["closure"]["verdict"] == "DISPROVEN"
    assert result["closure"]["state"] == "RECOVERED"
    assert verify_bundle(child, pin)["closure"]["verdict"] == "PROVEN"


@pytest.mark.parametrize("change", ["scope", "foreign-event", "drop-own-event", "old-version"])
def test_scope_chain_membership_and_version_fail_closed(two_targets, change):
    _, pin, original, _, _, _ = two_targets
    changed = copy.deepcopy(original)
    proof = changed["portable"]
    if change == "scope":
        proof["scope"]["foreign_transaction_semantics"] = "VERIFIED"
    elif change == "old-version":
        proof["version"] = "ace.portable.v1"
    else:
        events = proof["pages"][0]["events"]
        wanted = "tenant-b-change" if change == "foreign-event" else "tenant-a-change"
        index = next(
            i for i, item in enumerate(events) if item["payload"]["body"]["transaction_id"] == wanted
        )
        if change == "foreign-event":
            events[index]["signature"] = "0" * 128
        else:
            events.pop(index)
    with pytest.raises(ClosureError):
        verify_bundle(changed, pin)
    assert verify_bundle(original, pin)["closure"]["verdict"] == "PROVEN"


def test_scoped_kernel_preserves_O01_signed_ledgered_fail_omission_refusal(run, tmp_path):
    """Constructed, genuinely signed adversarial packet; never a claimed live target outcome."""
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    records = run["records"] + [_fail_sample(run)]
    immediate = packet(run, ledger, now=run["start"], records=records)
    assert immediate["payload"]["body"]["checks"]["protected-a"] == "FAIL"
    ledger.append(event(run, ledger, "OBSERVING", packet=immediate), ledger.head)
    history = ledger.audit_export()["events"]
    omitted = packet(run, ledger, records=run["records"])
    assert omitted["payload"]["body"]["verdict"] == "PROVEN"
    bogus = event(run, ledger, "PROVEN", packet=omitted)

    def checkpoint(last):
        return sign(
            run["keys"]["custodian"],
            "checkpoint",
            {
                "sequence": last["payload"]["body"]["sequence"],
                "head_hash": digest(last),
                "trust_hash": run["trust"].hash,
            },
            timestamp(run["start"]),
        )

    scope = [run["contract"]["transaction_id"]]
    with pytest.raises(ClosureError, match="LEDGERED_EVIDENCE_OMITTED"):
        ledger.replay_transaction_history([run["frozen"]], history + [bogus], checkpoint(bogus), scope)
    truthful = packet(run, ledger, records=records)
    assert truthful["payload"]["body"]["verdict"] == "DISPROVEN"
    final = event(run, ledger, "DISPROVEN", packet=truthful)
    result = ledger.replay_transaction_history([run["frozen"]], history + [final], checkpoint(final), scope)
    assert result["transactions"][scope[0]] == "DISPROVEN"
