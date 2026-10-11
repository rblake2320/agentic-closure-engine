import copy

import pytest

from closure_engine.crypto import sign
from closure_engine.protocol import digest, timestamp
from closure_engine.verdicts import evaluate


def judge(run, **changes):
    args = {k: run[k] for k in ["frozen", "binding", "records", "receipts", "store", "trust"]}
    args["now"] = run["start"] + 60_000
    args.update(changes)
    return evaluate(**args)


def replace(run, check, result="PASS", **changes):
    records = [r for r in run["records"] if r["observation"]["payload"]["body"]["check_id"] != check]
    records.append(run["observation"](check, result, **changes))
    return records


def test_A01_valid_control(run):
    assert judge(run).verdict == "PROVEN"


def test_A02_evaluator_tamper(run):
    assert judge(run, records=replace(run, "primary", "FAIL", tamper_detected=True)).verdict == "DISPROVEN"


@pytest.mark.parametrize("check", ["primary", "protected-a", "protected-b"])
def test_A04_A17_A18_failure_precedence(run, check):
    assert judge(run, records=replace(run, check, "FAIL"), receipts=[]).verdict == "DISPROVEN"


def test_A05_confirmed_missing_deployment_is_partial(run):
    receipt = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    receipt["status"] = "NOT_DEPLOYED"
    receipts = [sign(run["keys"]["broker"], "action-receipt", receipt, timestamp(run["start"]))]
    assert (
        judge(run, records=replace(run, "deployment", "NOT_COMPLETED"), receipts=receipts).verdict
        == "PARTIALLY_PROVEN"
    )


def test_A06_no_deployment_receipt_is_unknown(run):
    assert judge(run, receipts=[]).verdict == "INDETERMINATE"


def test_A07_unreachable_target(run):
    assert judge(run, records=replace(run, "primary", "UNKNOWN")).verdict == "INDETERMINATE"


def test_A08_unknown_side_effects_require_recovery(run):
    receipt = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    receipt["status"] = "UNKNOWN"
    result = judge(
        run, receipts=[sign(run["keys"]["broker"], "action-receipt", receipt, timestamp(run["start"]))]
    )
    assert result.verdict == "INDETERMINATE" and result.recovery_required


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("artifact_hash", digest(b"old"), "ARTIFACT_MISMATCH"),
        ("contract_hash", digest(b"foreign"), "CONTRACT_MISMATCH"),
        ("target_id", "another-target", "TARGET_MISMATCH"),
        ("attempt_id", "another-attempt", "ATTEMPT_MISMATCH"),
        ("evaluator_hash", digest(b"changed evaluator"), "EVALUATOR_MISMATCH"),
        ("nonce", "foreign-nonce", "CHALLENGE_MISMATCH"),
        ("transaction_id", "other-transaction", "TRANSACTION_MISMATCH"),
        ("phase", "window", "CHALLENGE_MISMATCH"),
    ],
)
def test_A03_A14_A15_binding_rejection(run, field, value, reason):
    result = judge(run, records=replace(run, "primary", **{field: value}))
    assert result.verdict == "INDETERMINATE"
    assert reason in [r["reason"] for r in result.rejected]


def test_A12_stale_evidence(run):
    result = judge(run, now=run["start"] + 180_001)
    assert result.verdict == "INDETERMINATE"
    assert "STALE_EVIDENCE" in [r["reason"] for r in result.rejected]


def test_A13_signature_failure(run):
    records = copy.deepcopy(run["records"])
    records[0]["observation"]["signature"] = "00" * 64
    assert judge(run, records=records).verdict == "INDETERMINATE"


def test_A14_exact_retry_does_not_add_sample(run):
    result = judge(run, records=run["records"] + [run["records"][0]])
    assert result.verdict == "PROVEN"
    assert result.admitted == judge(run).admitted


@pytest.mark.parametrize("offset", [0, 10_000, 59_999])
def test_A16_window_incomplete(run, offset):
    assert judge(run, now=run["start"] + offset).verdict == "INDETERMINATE"


def test_A16_sampling_gap(run):
    records = [
        r
        for r in run["records"]
        if not (
            r["observation"]["payload"]["body"]["check_id"] == "protected-a"
            and r["observation"]["payload"]["body"]["nonce"].endswith("-1")
        )
    ]
    assert judge(run, records=records).verdict == "INDETERMINATE"


def test_A20_evidence_bytes_tampered(run):
    first_hash = run["records"][0]["observation"]["payload"]["body"]["evidence_hash"]
    run["store"].path_for(first_hash).write_bytes(b"changed")
    assert judge(run).verdict == "INDETERMINATE"


def test_A26_permutation_determinism(run):
    assert judge(run).to_dict() == judge(run, records=list(reversed(run["records"]))).to_dict()


def test_A27_future_evidence(run):
    result = judge(run, records=replace(run, "primary", offset=90_000))
    assert result.verdict == "INDETERMINATE"
    assert "FUTURE_EVIDENCE" in [r["reason"] for r in result.rejected]


def test_A11_valid_controls_are_accepted_repeatedly(run):
    assert [judge(run).verdict for _ in range(5)] == ["PROVEN"] * 5


def test_conflicting_signed_observations_cannot_close(run):
    contradictory = run["observation"]("primary", "UNKNOWN")
    result = judge(run, records=run["records"] + [contradictory])
    assert result.verdict == "INDETERMINATE"


def test_missing_baseline_observation_cannot_close(run):
    records = [r for r in run["records"] if r["observation"]["payload"]["body"]["check_id"] != "baseline"]
    assert judge(run, records=records).verdict == "INDETERMINATE"
