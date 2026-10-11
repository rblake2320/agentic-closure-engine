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

# --- Follow-up coverage: two enrolled verifiers and differing receipt IDs -------------------------
# Builds a second TrustStore and rebinds the contract inside each test; shared fixtures are untouched.

from closure_engine.contracts import freeze  # noqa: E402
from closure_engine.crypto import Identity, TrustStore  # noqa: E402
from closure_engine.protocol import POLICY_HASH, digest  # noqa: E402
from closure_engine.store import EvidenceStore  # noqa: E402

V1, V2 = "verifier-01", "verifier-02"
ROLES = ("owner", "actor", "broker", "verifier", "authority", "custodian")


def multi_run(run, tmp_path):
    keys = dict(run["keys"])
    keys["verifier2"] = Identity.generate("verifier", V2)
    checks = [c["id"] for c in run["contract"]["checks"]]
    trust = TrustStore.from_identities(
        [keys[r] for r in ROLES] + [keys["verifier2"]], verifier_checks=checks
    )
    contract = copy.deepcopy(run["contract"])
    contract["trust_hash"] = trust.hash
    for c in contract["checks"]:
        if c["id"] == "primary":
            c["observers"] = [V1, V2]
    approval = sign(
        keys["owner"],
        "approval",
        {"contract_hash": digest(contract), "trust_hash": trust.hash, "policy_hash": POLICY_HASH},
        timestamp(run["start"]),
    )
    frozen = freeze(contract, approval, trust)
    challenges = []
    for c in contract["checks"]:
        for i in range(3 if c["phase"] == "window" else 1):
            nonce = c["id"] + "-nonce-" + str(i)
            challenges.append({"nonce": nonce, "check_id": c["id"], "phase": c["phase"]})
    binding = sign(
        keys["authority"],
        "run-binding",
        {
            "transaction_id": contract["transaction_id"],
            "attempt_id": contract["attempt_id"],
            "contract_hash": frozen.hash,
            "artifact_hash": run["artifact"],
            "target_id": contract["target_id"],
            "window_start": timestamp(run["start"]),
            "challenges": challenges,
        },
        timestamp(run["start"]),
    )
    store = EvidenceStore(tmp_path / "multi-evidence")
    m = dict(
        keys=keys, trust=trust, frozen=frozen, binding=binding, store=store, contract=contract,
        start=run["start"], artifact=run["artifact"],
    )

    def observe(verifier_identity, check_id, result="PASS", index=0, offset=0):
        check = next(c for c in contract["checks"] if c["id"] == check_id)
        if check_id == "baseline":
            raw, artifact = b"baseline artifact", run["baseline"]
        else:
            raw = ("multi " + check_id + str(index) + result + verifier_identity.issuer).encode()
            artifact = run["artifact"]
        body = {
            "observation_id": check_id + "-obs-" + verifier_identity.issuer + str(index),
            "transaction_id": contract["transaction_id"],
            "attempt_id": contract["attempt_id"],
            "contract_hash": frozen.hash,
            "artifact_hash": artifact,
            "target_id": contract["target_id"],
            "check_id": check_id,
            "evaluator_hash": contract["evaluator_hash"],
            "policy_hash": POLICY_HASH,
            "nonce": check_id + "-nonce-" + str(index),
            "phase": check["phase"],
            "observed_at": timestamp(run["start"] + offset),
            "result": result,
            "evidence_hash": store.put(raw),
            "tamper_detected": False,
        }
        obs = sign(verifier_identity, "observation", body, body["observed_at"])
        ingestion = sign(
            keys["custodian"],
            "ingestion",
            {"envelope_hash": digest(obs), "received_at": body["observed_at"]},
            body["observed_at"],
        )
        return {"observation": obs, "ingestion": ingestion}

    base = []
    for c in contract["checks"]:
        if c["id"] == "primary":
            continue
        for i in range(3 if c["phase"] == "window" else 1):
            base.append(observe(keys["verifier"], c["id"], index=i, offset=i * 30_000))
    m["base"] = base
    m["observe"] = observe
    m["receipts"] = [m_receipt(m, "EXECUTED")]
    return m


def m_receipt(m, status, receipt_id="deploy-1"):
    c = m["contract"]
    body = {
        "receipt_id": receipt_id,
        "transaction_id": c["transaction_id"],
        "attempt_id": c["attempt_id"],
        "contract_hash": m["frozen"].hash,
        "artifact_hash": m["artifact"],
        "target_id": c["target_id"],
        "operation": "deploy",
        "status": status,
        "recorded_at": timestamp(m["start"]),
    }
    return sign(m["keys"]["broker"], "action-receipt", body, timestamp(m["start"]))


def multi_judge(m, records=(), receipts=None):
    return evaluate(
        frozen=m["frozen"],
        binding=m["binding"],
        records=m["base"] + list(records),
        receipts=m["receipts"] if receipts is None else receipts,
        store=m["store"],
        trust=m["trust"],
        now=m["start"] + 60_000,
    )


def assert_only_conflict_rejected(result):
    # Receipts and contract binding were admitted; the only rejections are the conflicting observations.
    assert {r["reason"] for r in result.rejected} <= {"REPLAYED_OR_CONFLICTING_OBSERVATION"}
    assert result.verdict in {"DISPROVEN", "INDETERMINATE"}
    assert result.checks["primary"] in {"FAIL", "UNKNOWN"}


def test_F06_11_two_verifiers_pass_vs_fail_conflict_order_invariant(run, tmp_path):
    m = multi_run(run, tmp_path)
    conflict = [m["observe"](m["keys"]["verifier"], "primary", "PASS"),
                m["observe"](m["keys"]["verifier2"], "primary", "FAIL")]
    first = multi_judge(m, records=conflict)
    assert_only_conflict_rejected(first)
    assert first.to_dict() == multi_judge(m, records=list(reversed(conflict))).to_dict()


def test_F06_12_two_verifiers_fail_vs_pass_conflict_order_invariant(run, tmp_path):
    m = multi_run(run, tmp_path)
    conflict = [m["observe"](m["keys"]["verifier"], "primary", "FAIL"),
                m["observe"](m["keys"]["verifier2"], "primary", "PASS")]
    first = multi_judge(m, records=conflict)
    assert_only_conflict_rejected(first)
    assert first.to_dict() == multi_judge(m, records=list(reversed(conflict))).to_dict()


def test_F06_13_different_receipt_ids_executed_vs_not_deployed_unresolved(run, tmp_path):
    m = multi_run(run, tmp_path)
    receipts = [m_receipt(m, "EXECUTED", "deploy-1"), m_receipt(m, "NOT_DEPLOYED", "deploy-2")]
    primary = [m["observe"](m["keys"]["verifier2"], "primary", "PASS")]
    result = multi_judge(m, records=primary, receipts=receipts)
    assert result.rejected == []
    assert result.verdict == "INDETERMINATE"
    assert result.reason_codes == ["REQUIRED_EVIDENCE_UNRESOLVED"]
    assert result.recovery_required is True
    assert result.to_dict() == multi_judge(m, records=primary, receipts=list(reversed(receipts))).to_dict()


def test_F06_14_valid_multi_verifier_control_proven(run, tmp_path):
    m = multi_run(run, tmp_path)
    result = multi_judge(m, records=[m["observe"](m["keys"]["verifier2"], "primary", "PASS")])
    assert result.rejected == []
    assert result.verdict == "PROVEN"
