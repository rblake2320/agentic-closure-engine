"""Acceptance policy v3: opt-in confirmed primary non-completion (root decision A).

A primary NOT_COMPLETED counts only for a frozen opt-in primary, under an authenticated
NOT_DEPLOYED receipt, with the deployment check NOT_COMPLETED and an independent baseline
read-back (baseline check PASS). Any qualified FAIL is DISPROVEN; unknown, divergent or
conflicting state is never partial. Policy v2 contracts and retained v2 packets replay unchanged.
"""

import copy
import json
from pathlib import Path

import pytest

from closure_engine.contracts import freeze
from closure_engine.crypto import TrustStore, sign
from closure_engine.protocol import POLICY_HASH, ClosureError, digest, timestamp

try:
    from closure_engine.protocol import POLICY_V2
except ImportError:  # pre-v3 kernels: the only policy is v2
    POLICY_V2 = POLICY_HASH
from closure_engine.store import EvidenceStore
from closure_engine.verdicts import evaluate, replay_packet

FIXTURES = Path(__file__).parent / "fixtures" / "policy_v2_live_http"


def variant(run, *, policy=POLICY_HASH, primary_allow=True):
    """Re-approve the fixture contract under ``policy`` with the primary opt-in set as given."""
    c = copy.deepcopy(run["contract"])
    c["policy_hash"] = policy
    for check in c["checks"]:
        if check["kind"] == "primary":
            check["allow_not_completed"] = primary_allow
    approval = sign(
        run["keys"]["owner"],
        "approval",
        {"contract_hash": digest(c), "trust_hash": run["trust"].hash, "policy_hash": policy},
        timestamp(run["start"]),
    )
    frozen = freeze(c, approval, run["trust"])
    body = copy.deepcopy(run["binding"]["payload"]["body"])
    body["contract_hash"] = frozen.hash
    binding = sign(run["keys"]["authority"], "run-binding", body, timestamp(run["start"]))
    return c, frozen, binding


def observe(run, c, frozen, check_id, result, index=0, offset=0, **changes):
    check = next(ch for ch in c["checks"] if ch["id"] == check_id)
    raw = ("policy-v3 " + check_id + str(index) + result).encode()
    if check_id == "baseline":
        raw = b"baseline artifact"
    body = {
        "observation_id": f"{check_id}-v3-{index}-{result}",
        "transaction_id": c["transaction_id"],
        "attempt_id": c["attempt_id"],
        "contract_hash": frozen.hash,
        "artifact_hash": run["baseline"] if check_id == "baseline" else run["artifact"],
        "target_id": c["target_id"],
        "check_id": check_id,
        "evaluator_hash": c["evaluator_hash"],
        "policy_hash": c["policy_hash"],
        "nonce": check_id + "-nonce-" + str(index),
        "phase": check["phase"],
        "observed_at": timestamp(run["start"] + offset),
        "result": result,
        "evidence_hash": run["store"].put(raw),
        "tamper_detected": False,
        **changes,
    }
    obs = sign(run["keys"]["verifier"], "observation", body, body["observed_at"])
    ing = sign(
        run["keys"]["custodian"],
        "ingestion",
        {"envelope_hash": digest(obs), "received_at": body["observed_at"]},
        body["observed_at"],
    )
    return {"observation": obs, "ingestion": ing}


def receipt(run, frozen, status, receipt_id="deploy-1"):
    body = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    body.update(contract_hash=frozen.hash, status=status, receipt_id=receipt_id)
    return sign(run["keys"]["broker"], "action-receipt", body, body["recorded_at"])


def records(run, c, frozen, overrides=None, extra=()):
    """One full observation set; ``overrides`` maps check id -> result for every sample."""
    overrides = overrides or {}
    out = []
    for check in c["checks"]:
        for i in range(3 if check["phase"] == "window" else 1):
            default = "NOT_COMPLETED" if check["kind"] == "deployment" else "PASS"
            out.append(
                observe(run, c, frozen, check["id"], overrides.get(check["id"], default), i, i * 30_000)
            )
    return out + list(extra)


def judge(run, frozen, binding, recs, receipts):
    return evaluate(frozen, binding, recs, receipts, run["store"], run["trust"], run["start"] + 60_000)


PRIMARY_NC = {"primary": "NOT_COMPLETED"}


def test_policy_v3_is_the_current_policy_and_v2_is_retained():
    assert POLICY_HASH != POLICY_V2


def test_v3_opt_in_confirmed_non_deployment_is_partially_proven(run):
    c, frozen, binding = variant(run)
    result = judge(
        run, frozen, binding, records(run, c, frozen, PRIMARY_NC), [receipt(run, frozen, "NOT_DEPLOYED")]
    )
    assert result.verdict == "PARTIALLY_PROVEN" and result.reason_codes == ["CONFIRMED_NON_COMPLETION"]
    assert result.checks["primary"] == "NOT_COMPLETED" and result.checks["deployment"] == "NOT_COMPLETED"


def test_qualified_fail_still_disproves(run):
    c, frozen, binding = variant(run)
    recs = records(run, c, frozen, {**PRIMARY_NC, "protected-a": "FAIL"})
    assert judge(run, frozen, binding, recs, [receipt(run, frozen, "NOT_DEPLOYED")]).verdict == "DISPROVEN"


def test_primary_fail_with_non_deployment_still_disproves(run):
    c, frozen, binding = variant(run)
    recs = records(run, c, frozen, {"primary": "FAIL"})
    assert judge(run, frozen, binding, recs, [receipt(run, frozen, "NOT_DEPLOYED")]).verdict == "DISPROVEN"


@pytest.mark.parametrize("status", ["EXECUTED", "UNKNOWN"])
def test_receipt_other_than_not_deployed_is_never_partial(run, status):
    c, frozen, binding = variant(run)
    recs = records(run, c, frozen, PRIMARY_NC)
    assert judge(run, frozen, binding, recs, [receipt(run, frozen, status)]).verdict == "INDETERMINATE"


def test_conflicting_receipts_are_never_partial(run):
    c, frozen, binding = variant(run)
    recs = records(run, c, frozen, PRIMARY_NC)
    receipts = [receipt(run, frozen, "NOT_DEPLOYED", "a"), receipt(run, frozen, "EXECUTED", "b")]
    assert judge(run, frozen, binding, recs, receipts).verdict == "INDETERMINATE"


def test_missing_receipt_is_never_partial(run):
    c, frozen, binding = variant(run)
    assert judge(run, frozen, binding, records(run, c, frozen, PRIMARY_NC), []).verdict == "INDETERMINATE"


def test_divergent_target_state_is_disproven(run):
    c, frozen, binding = variant(run)
    recs = records(run, c, frozen, {**PRIMARY_NC, "deployment": "FAIL"})
    assert judge(run, frozen, binding, recs, [receipt(run, frozen, "NOT_DEPLOYED")]).verdict == "DISPROVEN"


def test_deployed_state_with_primary_not_completed_is_never_partial(run):
    c, frozen, binding = variant(run)
    recs = records(run, c, frozen, {**PRIMARY_NC, "deployment": "PASS"})
    assert (
        judge(run, frozen, binding, recs, [receipt(run, frozen, "NOT_DEPLOYED")]).verdict == "INDETERMINATE"
    )


def test_missing_independent_baseline_read_back_is_never_partial(run):
    c, frozen, binding = variant(run)
    recs = [
        r
        for r in records(run, c, frozen, PRIMARY_NC)
        if r["observation"]["payload"]["body"]["check_id"] != "baseline"
    ]
    assert (
        judge(run, frozen, binding, recs, [receipt(run, frozen, "NOT_DEPLOYED")]).verdict == "INDETERMINATE"
    )


def test_conflicting_primary_samples_are_never_partial(run):
    c, frozen, binding = variant(run)
    conflicting = observe(run, c, frozen, "primary", "PASS", 0, 0, observation_id="primary-other")
    recs = records(run, c, frozen, PRIMARY_NC, extra=[conflicting])
    assert (
        judge(run, frozen, binding, recs, [receipt(run, frozen, "NOT_DEPLOYED")]).verdict == "INDETERMINATE"
    )


def test_without_opt_in_primary_not_completed_is_rejected(run):
    c, frozen, binding = variant(run, primary_allow=False)
    result = judge(
        run, frozen, binding, records(run, c, frozen, PRIMARY_NC), [receipt(run, frozen, "NOT_DEPLOYED")]
    )
    assert result.verdict == "INDETERMINATE"
    assert any(r["reason"] == "INVALID_PARTIAL_RESULT" for r in result.rejected)


def test_policy_v2_cannot_opt_primary_into_non_completion(run):
    with pytest.raises(ClosureError, match="INVALID_PARTIAL_POLICY"):
        variant(run, policy=POLICY_V2, primary_allow=True)


def test_unknown_policy_is_refused(run):
    with pytest.raises(ClosureError, match="POLICY_OR_TRUST_MISMATCH"):
        variant(run, policy="sha256:" + "9" * 64, primary_allow=False)


def test_policy_v2_contract_evaluates_and_replays_under_v2_rules(run, tmp_path):
    from closure_engine.crypto import Identity  # noqa: F401
    from closure_engine.verdicts import close_run

    c, frozen, binding = variant(run, policy=POLICY_V2, primary_allow=False)
    recs = records(run, c, frozen, {"deployment": "PASS"})
    receipts = [receipt(run, frozen, "EXECUTED")]
    packet = close_run(
        frozen=frozen,
        binding=binding,
        records=recs,
        receipts=receipts,
        store=run["store"],
        trust=run["trust"],
        now=run["start"] + 60_000,
        authority=run["keys"]["authority"],
        ledger_head="sha256:" + "0" * 64,
    )
    body = replay_packet(packet, run["store"], run["trust"])
    assert body["policy_hash"] == POLICY_V2 and body["verdict"] == "PROVEN"


@pytest.mark.parametrize(("case", "verdict"), [("valid", "PROVEN"), ("protected-state-failure", "DISPROVEN")])
def test_retained_real_v2_packets_still_replay(case, verdict):
    folder = FIXTURES / case
    trust = TrustStore.from_dict(json.loads((folder / "trust.json").read_bytes()))
    packet = json.loads((folder / "live-tx-packet.json").read_bytes())
    body = replay_packet(packet, EvidenceStore(folder / "evidence", create=False), trust)
    assert body["verdict"] == verdict and body["policy_hash"] == POLICY_V2
