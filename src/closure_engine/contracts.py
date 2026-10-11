"""Freeze exact approved contract bytes; return immutable storage and fresh views."""

from dataclasses import dataclass

from .crypto import verify
from .protocol import (
    ACCEPTED_POLICIES,
    PARTIAL_KINDS,
    ClosureError,
    canonical,
    digest,
    milliseconds,
    strict_loads,
    validate,
)


@dataclass(frozen=True)
class FrozenContract:
    raw: bytes
    approval_raw: bytes

    @property
    def hash(self):
        return digest(self.raw)

    @property
    def data(self):
        return strict_loads(self.raw)

    @property
    def approval(self):
        return strict_loads(self.approval_raw)


def freeze(contract, approval, trust):
    validate("closure-contract", contract)
    proof = verify(approval, "approval", trust)
    policy = contract["policy_hash"]
    if contract["trust_hash"] != trust.hash or policy not in ACCEPTED_POLICIES:
        raise ClosureError("POLICY_OR_TRUST_MISMATCH")
    if proof != {"contract_hash": digest(contract), "trust_hash": trust.hash, "policy_hash": policy}:
        raise ClosureError("APPROVAL_MISMATCH")
    ids = [c["id"] for c in contract["checks"]]
    if len(set(ids)) != len(ids):
        raise ClosureError("DUPLICATE_CHECK")
    for check in contract["checks"]:
        for observer in check["observers"]:
            enrolled = [r for r in trust.data["keys"] if r["issuer"] == observer]
            if not enrolled or any(
                r["role"] != "verifier" or check["id"] not in r["checks"] for r in enrolled
            ):
                raise ClosureError("OBSERVER_NOT_AUTHORIZED")
    mandatory = [c for c in contract["checks"] if c["mandatory"]]
    kinds = {c["kind"] for c in mandatory}
    if not {"primary", "invariant", "deployment", "stage", "baseline"} <= kinds:
        raise ClosureError("INCOMPLETE_ACCEPTANCE_CONTRACT")
    if sum(c["kind"] == "invariant" for c in mandatory) < 2:
        raise ClosureError("INSUFFICIENT_INVARIANTS")
    if any(c["allow_not_completed"] and c["kind"] not in PARTIAL_KINDS[policy] for c in contract["checks"]):
        raise ClosureError("INVALID_PARTIAL_POLICY")
    window = contract["window"]
    if window["max_age_ms"] < window["duration_ms"] or (
        (window["min_samples"] - 1) * window["max_gap_ms"] < window["duration_ms"]
    ):
        raise ClosureError("UNSATISFIABLE_WINDOW")
    milliseconds(contract["deadline_at"])
    return FrozenContract(canonical(contract), canonical(approval))
