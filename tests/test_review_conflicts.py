"""F06: adversarial evidence-conflict tests on the existing run fixture.

Expectations are registered in docs/review/haiku-f06-results.md before execution.
Signature authentication establishes who signed an observation, not that the
observer was truthful; these tests do not claim otherwise.
"""

import copy

from closure_engine.crypto import sign
from closure_engine.protocol import timestamp
from closure_engine.verdicts import evaluate


def judge(run, **changes):
    args = {k: run[k] for k in ["frozen", "binding", "records", "receipts", "store", "trust"]}
    args["now"] = run["start"] + 60_000
    args.update(changes)
    return evaluate(**args)


def check_of(record):
    return record["observation"]["payload"]["body"]["check_id"]


def with_results(run, **results):
    """Replace every sample of the named checks with one fresh sample per result."""
    records = [r for r in run["records"] if check_of(r) not in results]
    for check_id, result in results.items():
        records.append(run["observation"](check_id, result))
    return records


def receipt(run, status, receipt_id="deploy-1"):
    body = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    body["status"] = status
    body["receipt_id"] = receipt_id
    return sign(run["keys"]["broker"], "action-receipt", body, timestamp(run["start"]))


def test_F06_01_signed_fail_on_one_window_sample_disproves(run):
    # Same authorized verifier: two PASS window samples and one FAIL. The FAIL wins.
    records = [
        r
        for r in run["records"]
        if not (check_of(r) == "protected-a" and r["observation"]["payload"]["body"]["nonce"].endswith("-0"))
    ]
    records.append(run["observation"]("protected-a", "FAIL", index=0))
    result = judge(run, records=records)
    assert result.verdict == "DISPROVEN"
    assert result.checks["protected-a"] == "FAIL"
    assert result.reason_codes == ["MANDATORY_CHECK_FAILED"]


def test_F06_02_unchallenged_signed_fail_is_rejected_not_counted(run):
    # A FAIL under a nonce that was never issued is rejected as evidence (CHALLENGE_MISMATCH).
    forged = run["observation"](
        "primary", "FAIL", observation_id="primary-obs-forged", nonce="primary-nonce-9"
    )
    result = judge(run, records=run["records"] + [forged])
    assert result.verdict == "PROVEN"
    assert "CHALLENGE_MISMATCH" in [r["reason"] for r in result.rejected]


def test_F06_03_signed_fail_on_patch_beats_passing_primary_and_receipt(run):
    result = judge(run, records=with_results(run, patch="FAIL"))
    assert result.verdict == "DISPROVEN"
    assert result.checks["primary"] == "PASS"
    assert result.checks["patch"] == "FAIL"


def test_F06_04_freshness_boundary_inclusive_at_max_age_then_stale(run):
    # Samples at offsets 0/30s/60s. max_age is 120s and the deadline is start+120s.
    at_boundary = judge(run, now=run["start"] + 120_000)
    assert at_boundary.verdict == "PROVEN"
    past_boundary = judge(run, now=run["start"] + 120_001)
    assert past_boundary.verdict == "INDETERMINATE"
    assert "STALE_EVIDENCE" in [r["reason"] for r in past_boundary.rejected]


def primary_at(run, offset):
    records = [r for r in run["records"] if check_of(r) != "primary"]
    records.append(run["observation"]("primary", "PASS", offset=offset))
    return records


def test_F06_05_clock_skew_boundary_inclusive_then_future_rejected(run):
    # max_clock_skew_ms is 1000. Primary observed at now+skew is admitted; one ms more is not.
    at_skew = judge(run, records=primary_at(run, 61_000))
    assert at_skew.verdict == "PROVEN"
    beyond = judge(run, records=primary_at(run, 61_001))
    assert beyond.verdict == "INDETERMINATE"
    assert "FUTURE_EVIDENCE" in [r["reason"] for r in beyond.rejected]


def test_F06_06_not_completed_deployment_with_executed_receipt_is_conflict(run):
    result = judge(run, records=with_results(run, deployment="NOT_COMPLETED"))
    assert result.verdict == "INDETERMINATE"
    assert result.reason_codes == ["CONFLICTING_EXECUTION_EVIDENCE"]


def test_F06_07_not_completed_deployment_plus_signed_fail_disproves(run):
    records = with_results(run, deployment="NOT_COMPLETED", patch="FAIL")
    result = judge(run, records=records, receipts=[receipt(run, "NOT_DEPLOYED")])
    assert result.verdict == "DISPROVEN"
    assert result.reason_codes == ["MANDATORY_CHECK_FAILED"]


def test_F06_08_not_completed_on_primary_is_rejected_and_unresolved(run):
    result = judge(run, records=with_results(run, primary="NOT_COMPLETED"))
    assert result.verdict == "INDETERMINATE"
    assert "INVALID_PARTIAL_RESULT" in [r["reason"] for r in result.rejected]


def test_F06_09_valid_control_confirmed_non_completion_is_partial(run):
    result = judge(
        run,
        records=with_results(run, deployment="NOT_COMPLETED"),
        receipts=[receipt(run, "NOT_DEPLOYED")],
    )
    assert result.verdict == "PARTIALLY_PROVEN"
    assert result.reason_codes == ["CONFIRMED_NON_COMPLETION"]
    assert result.recovery_required is False


def test_F06_10_valid_control_identical_receipt_is_not_a_conflict(run):
    # An exact duplicate receipt envelope dedupes by hash; it must not create a receipt conflict.
    duplicate = list(run["receipts"]) + list(run["receipts"])
    for _ in range(3):
        result = judge(run, receipts=duplicate)
        assert result.verdict == "PROVEN"
