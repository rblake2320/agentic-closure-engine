"""Opus independent review probes (2026-10-11). Each test asserts the boundary the
docs/threat model imply; a red result is a reported finding, not a weakened expectation."""

import copy

import pytest
from test_ledger import begin, event, packet
from test_recovery import parent_packet

from closure_engine.contracts import freeze
from closure_engine.crypto import sign
from closure_engine.protocol import GENESIS, POLICY_HASH, ClosureError, digest, timestamp
from closure_engine.recovery import recovery_status
from closure_engine.verdicts import close_run


def _fail_sample(run):
    """Authenticated, bound, fresh, challenged FAIL for protected-a sample 0."""
    return run["observation"]("protected-a", result="FAIL", offset=0, index=0, observation_id="pa-fail-0")


# O-01: a qualified mandatory FAIL already admitted into the ledger (via the OBSERVING
# packet) must not be droppable from the terminal packet's input set.
def test_O01_control_ledgered_fail_retained_yields_disproven(run, tmp_path):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    records = run["records"] + [_fail_sample(run)]
    immediate = packet(run, ledger, now=run["start"], records=records)
    assert immediate["payload"]["body"]["verdict"] == "DISPROVEN"
    ledger.append(event(run, ledger, "OBSERVING", packet=immediate), ledger.head)
    final = packet(run, ledger, records=records)
    assert final["payload"]["body"]["verdict"] == "DISPROVEN"


def test_O01_terminal_packet_cannot_omit_ledgered_mandatory_fail(run, tmp_path):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    fail = _fail_sample(run)
    immediate = packet(run, ledger, now=run["start"], records=run["records"] + [fail])
    assert immediate["payload"]["body"]["verdict"] == "DISPROVEN"
    assert immediate["payload"]["body"]["checks"]["protected-a"] == "FAIL"
    ledger.append(event(run, ledger, "OBSERVING", packet=immediate), ledger.head)
    # Terminal packet replays exactly over a retained input set that silently omits the FAIL.
    omitted = packet(run, ledger, records=run["records"])
    assert omitted["payload"]["body"]["verdict"] == "PROVEN"
    with pytest.raises(ClosureError):
        ledger.append(event(run, ledger, "PROVEN", packet=omitted), ledger.head)


# O-04: recovery coverage compares invariant IDs only. A child that keeps the IDs but
# downgrades the parent's 60 s window obligation to a single instant sample still recovers.
def _weakened_child(run, parent, phase="instant"):
    c = copy.deepcopy(run["contract"])
    c.update(
        transaction_id="recovery-1",
        attempt_id="restore-1",
        contract_id="recovery-contract",
        parent_packet_hash=digest(parent),
        baseline_hash=run["artifact"],
        deadline_at=timestamp(run["start"] + 180_000),
    )
    for ch in c["checks"]:
        if ch["kind"] == "invariant":
            ch["phase"] = phase
    approval = sign(
        run["keys"]["owner"],
        "approval",
        {"contract_hash": digest(c), "trust_hash": run["trust"].hash, "policy_hash": POLICY_HASH},
        timestamp(run["start"] + 60_000),
    )
    frozen = freeze(c, approval, run["trust"])
    n = {ch["id"]: (3 if ch["phase"] == "window" else 1) for ch in c["checks"]}
    challenges = [
        {"nonce": ch["id"] + "-r-" + str(i), "check_id": ch["id"], "phase": ch["phase"]}
        for ch in c["checks"]
        for i in range(n[ch["id"]])
    ]
    t0 = run["start"] + 60_000
    b = {
        "transaction_id": c["transaction_id"],
        "attempt_id": c["attempt_id"],
        "contract_hash": frozen.hash,
        "artifact_hash": run["baseline"],
        "target_id": c["target_id"],
        "window_start": timestamp(t0),
        "challenges": challenges,
    }
    binding = sign(run["keys"]["authority"], "run-binding", b, timestamp(t0))
    records = []
    for ch in c["checks"]:
        for i in range(n[ch["id"]]):
            observed = timestamp(t0 + i * 30_000)
            raw = (
                b"candidate artifact"
                if ch["kind"] == "baseline"
                else ("restore " + ch["id"] + str(i)).encode()
            )
            body = {
                "observation_id": ch["id"] + "-r-obs-" + str(i),
                "transaction_id": c["transaction_id"],
                "attempt_id": c["attempt_id"],
                "contract_hash": frozen.hash,
                "artifact_hash": c["baseline_hash"] if ch["kind"] == "baseline" else run["baseline"],
                "target_id": c["target_id"],
                "check_id": ch["id"],
                "evaluator_hash": c["evaluator_hash"],
                "policy_hash": POLICY_HASH,
                "nonce": ch["id"] + "-r-" + str(i),
                "phase": ch["phase"],
                "observed_at": observed,
                "result": "PASS",
                "evidence_hash": run["store"].put(raw),
                "tamper_detected": False,
            }
            obs = sign(run["keys"]["verifier"], "observation", body, observed)
            ing = sign(
                run["keys"]["custodian"],
                "ingestion",
                {"envelope_hash": digest(obs), "received_at": observed},
                observed,
            )
            records.append({"observation": obs, "ingestion": ing})
    receipt = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    receipt.update(
        contract_hash=frozen.hash,
        transaction_id=c["transaction_id"],
        attempt_id=c["attempt_id"],
        artifact_hash=run["baseline"],
        recorded_at=timestamp(t0),
    )
    receipts = [sign(run["keys"]["broker"], "action-receipt", receipt, timestamp(t0))]
    child = close_run(
        frozen=frozen,
        binding=binding,
        records=records,
        receipts=receipts,
        store=run["store"],
        trust=run["trust"],
        now=run["start"] + 120_000,
        authority=run["keys"]["authority"],
        ledger_head=GENESIS,
    )
    return frozen, child


def test_O04_control_same_phase_child_recovers(run):
    parent = parent_packet(run)
    frozen, child = _weakened_child(run, parent, phase="window")
    assert child["payload"]["body"]["verdict"] == "PROVEN"
    status = recovery_status(
        parent, frozen, child, run["trust"], run["start"] + 120_000, 120_000, store=run["store"]
    )
    assert status["state"] == "RECOVERED"


def test_O04_child_cannot_downgrade_parent_window_invariant_to_instant(run):
    parent = parent_packet(run)
    frozen, child = _weakened_child(run, parent, phase="instant")
    assert child["payload"]["body"]["verdict"] == "PROVEN"
    with pytest.raises(ClosureError, match="RECOVERY_COVERAGE_MISMATCH"):
        recovery_status(
            parent, frozen, child, run["trust"], run["start"] + 120_000, 120_000, store=run["store"]
        )
