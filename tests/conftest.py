import copy

import pytest

from closure_engine.contracts import freeze
from closure_engine.crypto import Identity, TrustStore, sign
from closure_engine.protocol import POLICY_HASH, digest, timestamp
from closure_engine.store import EvidenceStore


@pytest.fixture
def run(tmp_path):
    keys = {
        role: Identity.generate(role, role + "-01")
        for role in ("owner", "actor", "broker", "verifier", "authority", "custodian")
    }
    trust = TrustStore.from_identities(
        list(keys.values()),
        verifier_checks=[
            "primary",
            "protected-a",
            "protected-b",
            "deployment",
            "patch",
            "restore",
            "baseline",
        ],
    )
    start = 1_791_720_000_000
    evaluator = digest(b"operator-installed-evaluator-v1")
    baseline = digest(b"baseline artifact")
    artifact = digest(b"candidate artifact")
    contract = {
        "version": "v1",
        "contract_id": "contract-1",
        "revision": 1,
        "transaction_id": "transaction-1",
        "attempt_id": "attempt-1",
        "repo_id": "fixture/repo",
        "baseline_hash": baseline,
        "target_id": "fixture/local",
        "intent": "one bounded correction",
        "allowed_changes": ["app.py"],
        "protected_resources": ["config", "other-endpoint"],
        "allowed_actions": ["deploy"],
        "evaluator_hash": evaluator,
        "policy_hash": POLICY_HASH,
        "trust_hash": trust.hash,
        "deadline_at": timestamp(start + 120_000),
        "checks": [
            {
                "id": "primary",
                "kind": "primary",
                "mandatory": True,
                "phase": "instant",
                "observers": ["verifier-01"],
                "allow_not_completed": False,
            },
            {
                "id": "protected-a",
                "kind": "invariant",
                "mandatory": True,
                "phase": "window",
                "observers": ["verifier-01"],
                "allow_not_completed": False,
            },
            {
                "id": "protected-b",
                "kind": "invariant",
                "mandatory": True,
                "phase": "window",
                "observers": ["verifier-01"],
                "allow_not_completed": False,
            },
            {
                "id": "deployment",
                "kind": "deployment",
                "mandatory": True,
                "phase": "instant",
                "observers": ["verifier-01"],
                "allow_not_completed": True,
            },
            {
                "id": "patch",
                "kind": "stage",
                "mandatory": True,
                "phase": "instant",
                "observers": ["verifier-01"],
                "allow_not_completed": False,
            },
            {
                "id": "baseline",
                "kind": "baseline",
                "mandatory": True,
                "phase": "instant",
                "observers": ["verifier-01"],
                "allow_not_completed": False,
            },
        ],
        "window": {
            "duration_ms": 60_000,
            "max_gap_ms": 30_000,
            "min_samples": 3,
            "max_age_ms": 120_000,
            "max_clock_skew_ms": 1_000,
        },
        "recovery": {"mechanism": "redeploy-baseline", "deadline_ms": 120_000},
        "parent_packet_hash": None,
    }
    approval = sign(
        keys["owner"],
        "approval",
        {"contract_hash": digest(contract), "trust_hash": trust.hash, "policy_hash": POLICY_HASH},
        timestamp(start),
    )
    frozen = freeze(contract, approval, trust)
    challenges = []
    for c in contract["checks"]:
        for i in range(3 if c["phase"] == "window" else 1):
            challenges.append(
                {"nonce": c["id"] + "-nonce-" + str(i), "check_id": c["id"], "phase": c["phase"]}
            )
    binding_body = {
        "transaction_id": "transaction-1",
        "attempt_id": "attempt-1",
        "contract_hash": frozen.hash,
        "artifact_hash": artifact,
        "target_id": contract["target_id"],
        "window_start": timestamp(start),
        "challenges": challenges,
    }
    binding = sign(keys["authority"], "run-binding", binding_body, timestamp(start))
    store = EvidenceStore(tmp_path / "evidence")
    records = []

    def observation(check_id, result="PASS", offset=0, index=0, **changes):
        check = next(c for c in contract["checks"] if c["id"] == check_id)
        raw = ("independent fixture observation " + check_id + str(index) + result).encode()
        if check_id == "baseline":
            raw = b"baseline artifact"
        evidence_hash = store.put(raw)
        body = {
            "observation_id": check_id + "-obs-" + str(index),
            "transaction_id": contract["transaction_id"],
            "attempt_id": contract["attempt_id"],
            "contract_hash": frozen.hash,
            "artifact_hash": artifact,
            "target_id": contract["target_id"],
            "check_id": check_id,
            "evaluator_hash": evaluator,
            "policy_hash": POLICY_HASH,
            "nonce": check_id + "-nonce-" + str(index),
            "phase": check["phase"],
            "observed_at": timestamp(start + offset),
            "result": result,
            "evidence_hash": evidence_hash,
            "tamper_detected": False,
        }
        body.update(changes)
        if check_id == "baseline" and "artifact_hash" not in changes:
            body["artifact_hash"] = baseline
        obs = sign(keys["verifier"], "observation", body, body["observed_at"])
        ingestion = sign(
            keys["custodian"],
            "ingestion",
            {"envelope_hash": digest(obs), "received_at": body["observed_at"]},
            body["observed_at"],
        )
        return {"observation": obs, "ingestion": ingestion}

    for c in contract["checks"]:
        for i in range(3 if c["phase"] == "window" else 1):
            records.append(observation(c["id"], offset=i * 30_000, index=i))
    receipt_body = {
        "receipt_id": "deploy-1",
        "transaction_id": "transaction-1",
        "attempt_id": "attempt-1",
        "contract_hash": frozen.hash,
        "artifact_hash": artifact,
        "target_id": contract["target_id"],
        "operation": "deploy",
        "status": "EXECUTED",
        "recorded_at": timestamp(start),
    }
    receipts = [sign(keys["broker"], "action-receipt", receipt_body, timestamp(start))]
    return dict(
        keys=keys,
        trust=trust,
        start=start,
        contract=contract,
        frozen=frozen,
        binding=binding,
        records=records,
        receipts=receipts,
        store=store,
        observation=observation,
        artifact=artifact,
        baseline=baseline,
        approval=approval,
        clone=copy.deepcopy,
    )
