"""Recovery is a separate verified transaction; never replace the parent verdict."""

from .contracts import freeze
from .crypto import verify
from .protocol import ClosureError, digest, milliseconds


def recovery_status(parent, child_frozen, child_packet, trust, now, deadline_ms):
    p = verify(parent, "closure-packet", trust)
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
    if result["artifact_hash"] != p["baseline_hash"]:
        return {"state": "RECOVERY_FAILED", "reason": "BASELINE_NOT_RESTORED"}
    parent_time = milliseconds(p["evaluated_at"])
    if milliseconds(result["window_start"]) < parent_time or (
        milliseconds(child_frozen.approval["payload"]["created_at"]) < parent_time
    ):
        raise ClosureError("RECOVERY_PRECEDES_PARENT")
    if milliseconds(result["evaluated_at"]) > now or milliseconds(result["evaluated_at"]) > deadline:
        return {"state": "RECOVERY_FAILED", "reason": "RECOVERY_DEADLINE_EXCEEDED"}
    if result["verdict"] == "PROVEN":
        return {"state": "RECOVERED", "reason": "RESTORATION_VERIFIED"}
    if result["verdict"] == "INDETERMINATE" and now < deadline:
        return {"state": "RECOVERY_REQUIRED", "reason": "RESTORATION_UNVERIFIED"}
    return {"state": "RECOVERY_FAILED", "reason": "RESTORATION_FAILED_OR_UNVERIFIED"}
