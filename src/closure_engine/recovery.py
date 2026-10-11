"""Recovery is a separate verified transaction; never replace the parent verdict."""

from .contracts import freeze
from .crypto import verify
from .protocol import ClosureError, digest, milliseconds, strict_loads


def recovery_status(parent, child_frozen, child_packet, trust, now, deadline_ms, *, store):
    from .verdicts import replay_packet

    p = verify(parent, "closure-packet", trust)
    replay_packet(parent, store, trust)
    parent_manifest = strict_loads(store.get(p["inputs_hash"]))
    parent_contract = parent_manifest["contract"]
    deadline = milliseconds(p["evaluated_at"]) + deadline_ms
    if child_packet is None:
        return {
            "state": "RECOVERY_FAILED" if now >= deadline else "RECOVERY_REQUIRED",
            "reason": "RESTORATION_UNVERIFIED",
        }
    freeze(child_frozen.data, child_frozen.approval, trust)
    c = child_frozen.data
    result = verify(child_packet, "closure-packet", trust)
    if c["parent_packet_hash"] != digest(parent) or result["parent_packet_hash"] != digest(parent):
        raise ClosureError("RECOVERY_PARENT_MISMATCH")
    if result["contract_hash"] != child_frozen.hash or result["target_id"] != p["target_id"]:
        raise ClosureError("RECOVERY_SUBJECT_MISMATCH")
    if c["target_id"] != p["target_id"] or c["baseline_hash"] != p["artifact_hash"]:
        raise ClosureError("RECOVERY_PRECONDITION_MISMATCH")
    parent_invariants = {
        ch["id"] for ch in parent_contract["checks"] if ch["kind"] == "invariant" and ch["mandatory"]
    }
    child_invariants = {ch["id"] for ch in c["checks"] if ch["kind"] == "invariant" and ch["mandatory"]}
    if set(c["protected_resources"]) != set(parent_contract["protected_resources"]) or (
        not parent_invariants <= child_invariants
    ):
        raise ClosureError("RECOVERY_COVERAGE_MISMATCH")
    children = {ch["id"]: ch for ch in c["checks"]}
    if any(canonical_check != children[canonical_check["id"]] for canonical_check in
           parent_contract["checks"] if canonical_check["id"] in parent_invariants):
        raise ClosureError("RECOVERY_COVERAGE_MISMATCH")
    stronger_min = ("duration_ms", "min_samples")
    stronger_max = ("max_gap_ms", "max_age_ms", "max_clock_skew_ms")
    if any(c["window"][key] < parent_contract["window"][key] for key in stronger_min) or (
        any(c["window"][key] > parent_contract["window"][key] for key in stronger_max)
    ) or c["evaluator_hash"] != parent_contract["evaluator_hash"]:
        raise ClosureError("RECOVERY_COVERAGE_MISMATCH")
    if result["artifact_hash"] != p["baseline_hash"]:
        return {"state": "RECOVERY_FAILED", "reason": "BASELINE_NOT_RESTORED"}
    parent_time = milliseconds(p["evaluated_at"])
    if milliseconds(result["window_start"]) < parent_time or (
        milliseconds(child_frozen.approval["payload"]["created_at"]) < parent_time
    ):
        raise ClosureError("RECOVERY_PRECEDES_PARENT")
    if milliseconds(result["evaluated_at"]) > now or milliseconds(result["evaluated_at"]) > deadline:
        return {"state": "RECOVERY_FAILED", "reason": "RECOVERY_DEADLINE_EXCEEDED"}
    replay_packet(child_packet, store, trust)
    if result["verdict"] == "PROVEN":
        return {"state": "RECOVERED", "reason": "RESTORATION_VERIFIED"}
    if result["verdict"] == "INDETERMINATE" and now < deadline:
        return {"state": "RECOVERY_REQUIRED", "reason": "RESTORATION_UNVERIFIED"}
    return {"state": "RECOVERY_FAILED", "reason": "RESTORATION_FAILED_OR_UNVERIFIED"}
