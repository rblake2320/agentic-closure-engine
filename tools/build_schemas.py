"""Regenerate committed v1 schemas; never called by the runtime."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src/closure_engine/schemas/v1"
ROOT.mkdir(parents=True, exist_ok=True)
S = {"type": "string", "minLength": 1, "maxLength": 512}
ID = {"type": "string", "pattern": r"^[A-Za-z0-9._:/-]{1,160}$"}
H = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
T = {"type": "string", "format": "date-time", "pattern": "Z$"}
B = {"type": "boolean"}
N = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}


def enum(*items):
    return {"enum": list(items)}


def arr(item, minimum=0, maximum=256):
    return {"type": "array", "items": item, "minItems": minimum, "maxItems": maximum}


def obj(**fields):
    return {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}


def nullable(schema):
    return {"anyOf": [schema, {"type": "null"}]}


def write(name, schema):
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:ace:v1:" + name,
        **schema,
    }
    (ROOT / (name + ".json")).write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


def signed(name, body):
    return obj(
        algorithm={"const": "Ed25519"},
        payload=obj(
            version={"const": "v1"}, purpose={"const": name}, issuer=ID, key_id=ID, created_at=T, body=body
        ),
        signature={"type": "string", "pattern": "^[0-9a-f]{128}$"},
    )


RESULT = enum("PASS", "FAIL", "UNKNOWN", "NOT_COMPLETED")
VERDICT = enum("PROVEN", "DISPROVEN", "PARTIALLY_PROVEN", "INDETERMINATE")
CHECKS = {
    "type": "object",
    "minProperties": 1,
    "maxProperties": 32,
    "additionalProperties": RESULT,
    "propertyNames": ID,
}
BASE = dict(transaction_id=ID, attempt_id=ID, contract_hash=H, artifact_hash=H, target_id=ID)
contract = obj(
    version={"const": "v1"},
    contract_id=ID,
    revision={"type": "integer", "minimum": 1},
    transaction_id=ID,
    attempt_id=ID,
    repo_id=ID,
    baseline_hash=H,
    target_id=ID,
    intent=S,
    allowed_changes=arr(S, 1, 32),
    protected_resources=arr(S, 2, 32),
    allowed_actions=arr(enum("deploy"), 1, 1),
    evaluator_hash=H,
    policy_hash=H,
    trust_hash=H,
    deadline_at=T,
    checks=arr(
        obj(
            id=ID,
            kind=enum("primary", "invariant", "deployment", "stage", "baseline"),
            mandatory=B,
            phase=enum("instant", "window"),
            observers=arr(ID, 1, 8),
            allow_not_completed=B,
        ),
        5,
        32,
    ),
    window=obj(
        duration_ms={"type": "integer", "minimum": 1, "maximum": 86_400_000},
        max_gap_ms={"type": "integer", "minimum": 1},
        min_samples={"type": "integer", "minimum": 2, "maximum": 256},
        max_age_ms=N,
        max_clock_skew_ms=N,
    ),
    recovery=obj(mechanism={"const": "redeploy-baseline"}, deadline_ms={"type": "integer", "minimum": 1}),
    parent_packet_hash=nullable(H),
)
write("closure-contract", contract)
write("recovery-contract", {**contract, "properties": {**contract["properties"], "parent_packet_hash": H}})
write(
    "trust-snapshot",
    obj(
        version={"const": "v1"},
        keys=arr(
            obj(
                key_id=ID,
                issuer=ID,
                role=enum("owner", "actor", "broker", "verifier", "authority", "custodian"),
                public_key={"type": "string", "pattern": "^[0-9a-f]{64}$"},
                checks=arr(ID),
            ),
            1,
            64,
        ),
    ),
)
bodies = {
    "approval": obj(contract_hash=H, trust_hash=H, policy_hash=H),
    "run-binding": obj(
        **BASE,
        window_start=T,
        challenges=arr(obj(nonce=ID, check_id=ID, phase=enum("instant", "window")), 1, 1024),
    ),
    "observation": obj(
        **BASE,
        observation_id=ID,
        check_id=ID,
        evaluator_hash=H,
        policy_hash=H,
        nonce=ID,
        phase=enum("instant", "window"),
        observed_at=T,
        result=RESULT,
        evidence_hash=H,
        tamper_detected=B,
    ),
    "ingestion": obj(envelope_hash=H, received_at=T),
    "action-receipt": obj(
        **BASE,
        receipt_id=ID,
        operation={"const": "deploy"},
        status=enum("EXECUTED", "NOT_DEPLOYED", "UNKNOWN"),
        recorded_at=T,
    ),
    "closure-packet": obj(
        **BASE,
        approval_hash=H,
        baseline_hash=H,
        evaluator_hash=H,
        policy_hash=H,
        trust_hash=H,
        binding_hash=H,
        inputs_hash=H,
        ledger_head=H,
        evaluated_at=T,
        window_start=T,
        window_end=T,
        parent_packet_hash=nullable(H),
        verdict=VERDICT,
        reason_codes=arr(ID),
        checks=CHECKS,
        admitted=arr(H, maximum=4096),
        rejected=arr(obj(hash=H, reason=ID), maximum=4096),
        window_complete=B,
        recovery_required=B,
    ),
    "checkpoint": obj(sequence=N, head_hash=H, trust_hash=H),
    "risk-acceptance": obj(packet_hash=H, contract_hash=H, rationale=S, expires_at=T),
}
for name, body in bodies.items():
    write(name, signed(name, body))
event = obj(
    event_id=ID,
    transaction_id=ID,
    contract_hash=H,
    sequence=N,
    previous_hash=H,
    state=enum(
        "DRAFT",
        "APPROVED",
        "FROZEN",
        "BASELINED",
        "EXECUTING",
        "VERIFYING",
        "OBSERVING",
        "PROVEN",
        "DISPROVEN",
        "PARTIALLY_PROVEN",
        "INDETERMINATE",
        "ACCEPTED",
        "RECOVERY_REQUIRED",
        "RECOVERED",
        "RECOVERY_FAILED",
        "RISK_ACCEPTED",
    ),
    refs=arr(H),
    packet=nullable(signed("closure-packet", bodies["closure-packet"])),
    binding=nullable(signed("run-binding", bodies["run-binding"])),
    receipt=nullable(signed("action-receipt", bodies["action-receipt"])),
    recovery_contract=nullable(contract),
    recovery_approval=nullable(signed("approval", bodies["approval"])),
    risk=nullable(signed("risk-acceptance", bodies["risk-acceptance"])),
)
write("ledger-event", signed("ledger-event", event))
write("evidence-envelope", signed("observation", bodies["observation"]))
