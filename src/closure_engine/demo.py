"""Explicitly synthetic deployment fixture with real artifact, crypto and ledger I/O."""

from pathlib import Path

from .contracts import freeze
from .crypto import Identity, TrustStore, sign
from .ledger import Ledger
from .protocol import POLICY_HASH, ClosureError, canonical, digest, timestamp
from .store import EvidenceStore
from .verdicts import close_run

SCENARIOS = (
    "valid",
    "invariant-failure",
    "evaluator-tamper",
    "old-artifact",
    "missing-deployment",
    "not-deployed",
    "unreachable",
    "signature-failure",
    "interrupted",
    "stale",
    "replay",
)


def public_write(path, value):
    path.write_bytes(canonical(value) + b"\n")


def demo(output, scenario="valid"):
    root = Path(output).resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ClosureError("OUTPUT_NOT_EMPTY")
    root.mkdir(parents=True, exist_ok=True)
    # Fixture principals only. These keys never leave memory or authorize a real deployment.
    keys = {
        role: Identity.generate(role, role + "-fixture")
        for role in ("owner", "actor", "broker", "verifier", "authority", "custodian")
    }
    ids = ["primary", "protected-a", "protected-b", "deployment", "patch", "baseline"]
    trust = TrustStore.from_identities(list(keys.values()), ids)
    start = 1_791_720_000_000  # Fixed fixture clock, not an assertion about observed real-world time.
    baseline_file, candidate_file = root / "baseline.bin", root / "candidate.bin"
    baseline_file.write_bytes(b"baseline artifact")
    candidate_file.write_bytes(b"candidate artifact")
    store = EvidenceStore(root / "evidence")
    baseline_hash = store.put(baseline_file.read_bytes())
    artifact_hash = store.put(candidate_file.read_bytes())
    evaluator_hash = digest(b"operator-pinned-fixture-evaluator-v1")
    checks = []
    for check_id, kind, phase in [
        ("primary", "primary", "instant"),
        ("protected-a", "invariant", "window"),
        ("protected-b", "invariant", "window"),
        ("deployment", "deployment", "instant"),
        ("patch", "stage", "instant"),
        ("baseline", "baseline", "instant"),
    ]:
        checks.append(
            {
                "id": check_id,
                "kind": kind,
                "phase": phase,
                "mandatory": True,
                "observers": [keys["verifier"].issuer],
                "allow_not_completed": kind == "deployment",
            }
        )
    contract = {
        "version": "v1",
        "contract_id": "fixture-contract",
        "revision": 1,
        "transaction_id": "fixture-transaction",
        "attempt_id": "fixture-attempt",
        "repo_id": "fixture/one-repository",
        "baseline_hash": baseline_hash,
        "target_id": "fixture/disposable-target",
        "intent": "offline kernel acceptance fixture",
        "allowed_changes": ["app.py"],
        "protected_resources": ["config", "other-endpoint"],
        "allowed_actions": ["deploy"],
        "evaluator_hash": evaluator_hash,
        "policy_hash": POLICY_HASH,
        "trust_hash": trust.hash,
        "deadline_at": timestamp(start + 120_000),
        "checks": checks,
        "window": {
            "duration_ms": 60_000,
            "max_gap_ms": 30_000,
            "min_samples": 3,
            "max_age_ms": 120_000,
            "max_clock_skew_ms": 1000,
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
    challenges = [
        {"nonce": c["id"] + "-nonce-" + str(i), "check_id": c["id"], "phase": c["phase"]}
        for c in checks
        for i in range(3 if c["phase"] == "window" else 1)
    ]
    binding_body = {
        "transaction_id": contract["transaction_id"],
        "attempt_id": contract["attempt_id"],
        "contract_hash": frozen.hash,
        "artifact_hash": artifact_hash,
        "target_id": contract["target_id"],
        "window_start": timestamp(start),
        "challenges": challenges,
    }
    binding = sign(keys["authority"], "run-binding", binding_body, timestamp(start))
    records = []
    for c in checks:
        for i in range(3 if c["phase"] == "window" else 1):
            observed = timestamp(start + i * 30_000)
            result = "PASS"
            tamper = scenario == "evaluator-tamper" and c["id"] == "primary"
            if scenario == "invariant-failure" and c["id"] == "protected-a" and i == 2:
                result = "FAIL"
            if tamper:
                result = "FAIL"
            if scenario == "unreachable" and c["id"] == "primary":
                result = "UNKNOWN"
            if scenario == "not-deployed" and c["id"] == "deployment":
                result = "NOT_COMPLETED"
            evidence = (
                baseline_file.read_bytes()
                if c["kind"] == "baseline"
                else canonical({"fixture": True, "check_id": c["id"], "sample": i, "result": result})
            )
            body = {
                "observation_id": c["id"] + "-obs-" + str(i),
                **{
                    k: binding_body[k]
                    for k in ("transaction_id", "attempt_id", "contract_hash", "artifact_hash", "target_id")
                },
                "check_id": c["id"],
                "evaluator_hash": evaluator_hash,
                "policy_hash": POLICY_HASH,
                "nonce": c["id"] + "-nonce-" + str(i),
                "phase": c["phase"],
                "observed_at": observed,
                "result": result,
                "evidence_hash": store.put(evidence),
                "tamper_detected": tamper,
            }
            if c["kind"] == "baseline":
                body["artifact_hash"] = baseline_hash
            if scenario == "old-artifact" and c["id"] == "primary":
                body["artifact_hash"] = baseline_hash
            observation = sign(keys["verifier"], "observation", body, observed)
            if scenario == "signature-failure" and c["id"] == "primary":
                observation["signature"] = "00" * 64
            ingestion = sign(
                keys["custodian"],
                "ingestion",
                {"envelope_hash": digest(observation), "received_at": observed},
                observed,
            )
            records.append({"observation": observation, "ingestion": ingestion})
    status = {"not-deployed": "NOT_DEPLOYED", "interrupted": "UNKNOWN"}.get(scenario, "EXECUTED")
    receipt = sign(
        keys["broker"],
        "action-receipt",
        {
            "receipt_id": "fixture-deploy-1",
            **{
                k: binding_body[k]
                for k in ("transaction_id", "attempt_id", "contract_hash", "artifact_hash", "target_id")
            },
            "operation": "deploy",
            "status": status,
            "recorded_at": timestamp(start),
        },
        timestamp(start),
    )
    receipts = [] if scenario == "missing-deployment" else [receipt]
    if scenario == "replay":
        records.append(records[0])
        receipts.append(receipt)
    now = start + (180_001 if scenario == "stale" else 60_000)
    ledger = Ledger(root / "ledger.sqlite", trust, store)
    ledger.register(frozen)

    def append(state, role, *, refs=None, packet=None, run_binding=None, action_receipt=None):
        body = {
            "event_id": "fixture-" + state,
            "transaction_id": contract["transaction_id"],
            "contract_hash": frozen.hash,
            "sequence": ledger.sequence + 1,
            "previous_hash": ledger.head,
            "state": state,
            "refs": refs or [],
            "packet": packet,
            "binding": run_binding,
            "receipt": action_receipt,
            "recovery_contract": None,
            "recovery_approval": None,
            "risk": None,
        }
        ledger.append(sign(keys[role], "ledger-event", body, timestamp(now)), ledger.head)

    for state, role in [("DRAFT", "actor"), ("APPROVED", "owner"), ("FROZEN", "authority")]:
        append(state, role)
    protected = {
        name: store.put(("actual fixture baseline " + name).encode())
        for name in contract["protected_resources"]
    }
    manifest = store.put(canonical({"artifact_hash": baseline_hash, "protected": protected}))
    append("BASELINED", "verifier", refs=[manifest])
    append("EXECUTING", "broker", run_binding=binding)
    args = dict(
        frozen=frozen,
        binding=binding,
        records=records,
        receipts=receipts,
        store=store,
        trust=trust,
        now=now,
        authority=keys["authority"],
    )
    if receipts and status != "UNKNOWN":
        append("VERIFYING", "broker", action_receipt=receipt)
        immediate = close_run(**{**args, "now": start}, ledger_head=ledger.head)
        if all(
            immediate["payload"]["body"]["checks"][c["id"]] == "PASS"
            for c in checks
            if c["mandatory"] and c["phase"] == "instant"
        ):
            append("OBSERVING", "authority", packet=immediate)
    packet = close_run(**args, ledger_head=ledger.head)
    verdict = packet["payload"]["body"]["verdict"]
    append(verdict, "authority", packet=packet)
    if verdict == "PROVEN":
        append("ACCEPTED", "owner")
    elif packet["payload"]["body"]["recovery_required"]:
        append("RECOVERY_REQUIRED", "authority")
    bundle = {
        "mode": "offline-fixture",
        "contract": contract,
        "approval": approval,
        "binding": binding,
        "records": records,
        "receipts": receipts,
    }
    public_write(root / "run.json", bundle)
    public_write(root / "trust.json", trust.data)
    public_write(root / "closure-packet.json", packet)
    public_write(root / "checkpoint.json", ledger.checkpoint(keys["custodian"], timestamp(now)))
    return {
        "mode": "offline-fixture",
        "scenario": scenario,
        "verdict": verdict,
        "state": ledger.state(contract["transaction_id"]),
        "evaluated_at": timestamp(now),
        "packet_hash": digest(packet),
        "artifact_hash": artifact_hash,
        "ledger_head": ledger.head,
        "output": str(root),
        "deployment_evidence": "synthetic",
        "crypto_artifact_and_ledger_io": "real",
    }
