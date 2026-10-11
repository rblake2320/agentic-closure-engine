import copy

import pytest

from closure_engine.contracts import freeze
from closure_engine.crypto import sign
from closure_engine.protocol import GENESIS, POLICY_HASH, ClosureError, digest, milliseconds, timestamp
from closure_engine.recovery import recovery_status
from closure_engine.verdicts import close_run


def parent_packet(run):
    return close_run(
        **{k: run[k] for k in ["frozen", "binding", "records", "receipts", "store", "trust"]},
        now=run["start"] + 60_000,
        authority=run["keys"]["authority"],
        ledger_head=GENESIS,
    )


def child_packet(run, parent, fail=False, wrong_target=False, protected_resources=None):
    c = copy.deepcopy(run["contract"])
    c.update(
        transaction_id="recovery-1",
        attempt_id="restore-1",
        contract_id="recovery-contract",
        parent_packet_hash=digest(parent),
        baseline_hash=run["artifact"],
        deadline_at=timestamp(run["start"] + 180_000),
    )
    if protected_resources is not None:
        c["protected_resources"] = protected_resources
    approval = sign(
        run["keys"]["owner"],
        "approval",
        {"contract_hash": digest(c), "trust_hash": run["trust"].hash, "policy_hash": POLICY_HASH},
        timestamp(run["start"] + 60_000),
    )
    frozen = freeze(c, approval, run["trust"])
    b = copy.deepcopy(run["binding"]["payload"]["body"])
    b.update(
        contract_hash=frozen.hash,
        transaction_id=c["transaction_id"],
        attempt_id=c["attempt_id"],
        artifact_hash=run["artifact"] if wrong_target else run["baseline"],
        window_start=timestamp(run["start"] + 60_000),
    )
    binding = sign(run["keys"]["authority"], "run-binding", b, timestamp(run["start"] + 60_000))
    records = []
    for pair in run["records"]:
        body = copy.deepcopy(pair["observation"]["payload"]["body"])
        body.update(
            contract_hash=frozen.hash,
            transaction_id=c["transaction_id"],
            attempt_id=c["attempt_id"],
            artifact_hash=b["artifact_hash"],
            observed_at=timestamp(milliseconds(body["observed_at"]) + 60_000),
        )
        if body["check_id"] == "baseline":
            body["artifact_hash"] = c["baseline_hash"]
            body["evidence_hash"] = run["store"].put(b"candidate artifact")
        if fail and body["check_id"] == "primary":
            body["result"] = "FAIL"
        obs = sign(run["keys"]["verifier"], "observation", body, body["observed_at"])
        ing = sign(
            run["keys"]["custodian"],
            "ingestion",
            {"envelope_hash": digest(obs), "received_at": body["observed_at"]},
            body["observed_at"],
        )
        records.append({"observation": obs, "ingestion": ing})
    receipt = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    receipt.update(
        contract_hash=frozen.hash,
        transaction_id=c["transaction_id"],
        attempt_id=c["attempt_id"],
        artifact_hash=b["artifact_hash"],
        recorded_at=timestamp(run["start"] + 60_000),
    )
    receipts = [sign(run["keys"]["broker"], "action-receipt", receipt, timestamp(run["start"] + 60_000))]
    packet = close_run(
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
    return frozen, packet


def test_recovery_cannot_drop_parent_protected_resources(run):
    parent = parent_packet(run)
    frozen, child = child_packet(run, parent, protected_resources=["unrelated-a", "unrelated-b"])
    with pytest.raises(ClosureError, match="RECOVERY_COVERAGE_MISMATCH"):
        recovery_status(
            parent, frozen, child, run["trust"], run["start"] + 120_000, 120_000, store=run["store"]
        )


@pytest.mark.parametrize(
    ("fail", "wrong_target", "expected"),
    [(False, False, "RECOVERED"), (True, False, "RECOVERY_FAILED"), (False, True, "RECOVERY_FAILED")],
)
def test_A09_A10_verified_recovery(run, fail, wrong_target, expected):
    parent = parent_packet(run)
    before = digest(parent)
    frozen, child = child_packet(run, parent, fail, wrong_target)
    result = recovery_status(
        parent, frozen, child, run["trust"], run["start"] + 120_000, 120_000, store=run["store"]
    )
    assert result["state"] == expected
    assert digest(parent) == before


def test_A25_missing_restoration_evidence(run):
    parent = parent_packet(run)
    assert (
        recovery_status(parent, None, None, run["trust"], run["start"] + 61_000, 120_000, store=run["store"])[
            "state"
        ]
        == "RECOVERY_REQUIRED"
    )
    assert (
        recovery_status(
            parent, None, None, run["trust"], run["start"] + 180_001, 120_000, store=run["store"]
        )["state"]
        == "RECOVERY_FAILED"
    )


def test_A24_wrong_recovery_precondition(run):
    parent = parent_packet(run)
    frozen, child = child_packet(run, parent)
    c = frozen.data
    c["baseline_hash"] = digest(b"newer legitimate deployment")
    approval = sign(
        run["keys"]["owner"],
        "approval",
        {"contract_hash": digest(c), "trust_hash": run["trust"].hash, "policy_hash": POLICY_HASH},
        timestamp(run["start"]),
    )
    changed = freeze(c, approval, run["trust"])
    # Also bind the child packet to this changed contract: identity alone cannot make recovery valid.
    body = copy.deepcopy(child["payload"]["body"])
    body.update(contract_hash=changed.hash, baseline_hash=c["baseline_hash"])
    changed_packet = sign(run["keys"]["authority"], "closure-packet", body, timestamp(run["start"] + 120_000))
    with pytest.raises(ClosureError, match="RECOVERY_PRECONDITION_MISMATCH"):
        recovery_status(
            parent, changed, changed_packet, run["trust"], run["start"] + 120_000, 120_000, store=run["store"]
        )


def test_recovery_cannot_use_pre_parent_observation_window(run):
    parent = parent_packet(run)
    frozen, child = child_packet(run, parent)
    body = copy.deepcopy(child["payload"]["body"])
    body["window_start"] = timestamp(run["start"])
    forged = sign(run["keys"]["authority"], "closure-packet", body, timestamp(run["start"] + 120_000))
    with pytest.raises(ClosureError, match="RECOVERY_PRECEDES_PARENT"):
        recovery_status(
            parent, frozen, forged, run["trust"], run["start"] + 120_000, 120_000, store=run["store"]
        )
