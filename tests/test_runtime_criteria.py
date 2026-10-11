"""Owner-approved primary criteria, judged over real HTTP. The actor's artifact never supplies
the expected value: the owner's frozen criterion does (and, for recovery, the value observed
before the change)."""

import json

import pytest
from test_runtime_e2e import WINDOW, artifact, run_to_verdict_child, world  # noqa: F401 - fixture

from closure_engine.protocol import ClosureError, canonical, digest
from closure_engine.runtime import Runtime
from closure_engine.runtime.service import contract_view
from closure_engine.runtime.target import TargetClient


def run(runtime, tx, raw, expect):
    runtime.propose("shop/api", tx, raw, intent="criteria", expect=expect, **WINDOW)
    for step in ("approve", "freeze", "baseline", "bind", "deploy"):
        getattr(runtime, step)(tx)
    runtime.observe(tx, phase="all")
    result = runtime.close(tx)
    return runtime.close(tx) if result["state"] == "OBSERVING" else result


def test_green_owner_value_served_is_proven(world):  # noqa: F811
    deployment, pin, _ = world
    result = run(Runtime(deployment, pin), "c-green", artifact(2), {"primary": 2})
    assert result["verdict"] == "PROVEN" and result["checks"]["primary"] == "PASS"


def test_red_actor_artifact_cannot_vouch_for_a_wrong_value(world):  # noqa: F811
    # The artifact deploys and serves answer=5 consistently; the owner asked for 2.
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    result = run(runtime, "c-red", artifact(5), {"primary": 2})
    assert result["verdict"] == "DISPROVEN"
    assert result["checks"]["primary"] == "FAIL"
    assert result["checks"]["deployment"] == "PASS" and result["checks"]["stage"] == "PASS"


def test_recovery_is_judged_against_the_original_observed_value(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    assert run(runtime, "c-bad", artifact(5), {"primary": 2})["verdict"] == "DISPROVEN"
    runtime.begin_recovery("c-bad")
    child = runtime.custody.tx("c-bad/recovery")
    assert child["contract"]["evaluator_hash"] == runtime.custody.tx("c-bad")["contract"]["evaluator_hash"]
    with pytest.raises(ClosureError, match="RECOVERY_CRITERIA_ARE_INHERITED"):
        runtime.propose("shop/api", "c-x", artifact(1), intent="x", expect={"primary": 1}, parent={})
    _, result = run_to_verdict_child(runtime, "c-bad/recovery")
    assert result["verdict"] == "PROVEN" and result["checks"]["primary"] == "PASS"
    assert runtime.complete_recovery("c-bad")["state"] == "RECOVERED"
    client = TargetClient(deployment.target("shop/api"))
    assert json.loads(client.get("/answer")[1]) == {"answer": 1}


def test_contract_view_shows_exact_criteria_the_owner_approves(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose("shop/api", "c-view", artifact(8), intent="review", expect={"primary": 8}, **WINDOW)
    view = runtime.contract("c-view")
    assert view["evaluator"]["criteria"] == {"primary": {"equals": 8, "restore_equals": 1}}
    assert digest(canonical(view["evaluator"])) == view["contract"]["evaluator_hash"]
    assert view["evaluator"]["profile"] == deployment.target("shop/api")
    assert contract_view(runtime.custody, runtime.custody.tx("c-view")) == view


@pytest.mark.parametrize(
    ("expect", "code"),
    [
        (None, "EXPECTATION_REQUIRED"),
        ({}, "EXPECTATION_REQUIRED"),
        ({"primary": 1}, "EXPECTATION_EQUALS_CURRENT"),
        ({"primary": 2, "other": 3}, "EXPECTATION_REQUIRED"),
    ],
)
def test_missing_or_degenerate_expectations_are_rejected(world, expect, code):  # noqa: F811
    deployment, pin, _ = world
    with pytest.raises(ClosureError, match=code):
        Runtime(deployment, pin).propose(
            "shop/api", "c-bad-expect", artifact(2), intent="x", expect=expect, **WINDOW
        )


def test_changed_probe_profile_is_refused_by_verifier(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose("shop/api", "c-prof", artifact(2), intent="profile", expect={"primary": 2}, **WINDOW)
    for step in ("approve", "freeze", "baseline", "bind", "deploy"):
        getattr(runtime, step)("c-prof")
    path = deployment.target_path("shop/api")
    profile = json.loads(path.read_bytes())
    profile["checks"][0]["probe"]["pointer"] = "/something-else"
    path.write_bytes(canonical(profile))  # operator file edited after approval
    with pytest.raises(ClosureError, match="EVALUATOR_MISMATCH"):
        runtime.observe("c-prof", phase="instant")
