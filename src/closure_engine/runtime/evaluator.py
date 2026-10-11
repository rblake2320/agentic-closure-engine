"""Evaluator bundle: the frozen, owner-approved definition of how a run is judged.

bundle = {
  "version": "v1",
  "target_id": ...,
  "profile": <operator-enrolled target profile, verbatim>,
  "criteria": {<primary check id>: {"equals": <owner's desired value>,
                                     "restore_equals": <value observed before the change>}}
}
The contract's evaluator_hash is digest(bundle), so the owner's approval signs the exact expected
values. The verifier fetches the bundle by that digest, requires its profile to equal the
operator-enrolled profile, and judges primary checks against these constants - never against
anything the actor's artifact asserts. Recovery transactions inherit the parent's bundle and are
judged against ``restore_equals``; the verifier confirms that value live before any deployment.
"""

from ..protocol import ClosureError, canonical, digest, strict_loads

PRIMARY_PROBES = {"http-json"}


def criteria_checks(profile):
    return [c for c in profile["checks"] if c["kind"] == "primary" and c["probe"]["type"] in PRIMARY_PROBES]


def build(profile, expect, restore):
    ids = {c["id"] for c in criteria_checks(profile)}
    if not isinstance(expect, dict) or set(expect) != ids:
        raise ClosureError("EXPECTATION_REQUIRED", ",".join(sorted(ids)))
    if set(restore) != ids:
        raise ClosureError("RESTORE_VALUE_REQUIRED")
    criteria = {}
    for check_id in sorted(ids):
        canonical(expect[check_id])  # bounded, canonical JSON only
        if canonical(expect[check_id]) == canonical(restore[check_id]):
            raise ClosureError("EXPECTATION_EQUALS_CURRENT", check_id)
        criteria[check_id] = {"equals": expect[check_id], "restore_equals": restore[check_id]}
    return {"version": "v1", "target_id": profile["target_id"], "profile": profile, "criteria": criteria}


def load(store, evaluator_hash, enrolled_profile):
    """Fetch and validate the bundle a contract names; refuse if the probe profile changed."""
    raw = store.get(evaluator_hash)
    if digest(raw) != evaluator_hash:
        raise ClosureError("EVALUATOR_MISMATCH")
    bundle = strict_loads(raw)
    if not isinstance(bundle, dict) or set(bundle) != {"version", "target_id", "profile", "criteria"}:
        raise ClosureError("EVALUATOR_INVALID")
    if bundle["version"] != "v1" or canonical(bundle["profile"]) != canonical(enrolled_profile):
        raise ClosureError("EVALUATOR_MISMATCH", "probe profile differs from operator enrollment")
    ids = {c["id"] for c in criteria_checks(bundle["profile"])}
    if set(bundle["criteria"]) != ids or any(
        set(v) != {"equals", "restore_equals"} for v in bundle["criteria"].values()
    ):
        raise ClosureError("EVALUATOR_INVALID")
    return bundle
