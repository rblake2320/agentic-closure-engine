"""Principal binding for independent approval (root's executed alias RED on PR #3, a6a4aa4).

Two findings, both registered here as unchanged negative expectations before the repair:
1. Alias: the same principal enrolled with an actor-only token and an owner-only token was
   accepted by ``validate_credentials`` in independent mode (per-token rule, not per-principal).
2. Sequence: a principal proposes as actor, its actor token is revoked, it is re-enrolled
   owner-only, and it approves its own proposal (no attribution bound to the transaction).

Repair: role union per principal across the whole enrolled snapshot, and the authenticated
proposer persisted in custody (the protected receiving boundary) and refused as approver.
"""

import base64
import hashlib
import json
import threading

import pytest
from test_runtime_api import call
from test_runtime_e2e import artifact
from test_runtime_e2e import world as world  # noqa:F401

from closure_engine.protocol import ClosureError
from closure_engine.runtime import Runtime
from closure_engine.runtime.api import ApiServer, load_credentials
from closure_engine.runtime.rpc import validate_credentials

ALICE_ACTOR = "alias-alice-actor-0123456789abcdef01234"
ALICE_OWNER = "alias-alice-owner-0123456789abcdef01234"
BOB_OWNER = "alias-bob-owner-0123456789abcdef0123456"
CAROL_AUTH = "alias-carol-auth-0123456789abcdef012345"
VIEWER = "alias-viewer-0123456789abcdef0123456789"
TOKENS = {
    ALICE_ACTOR: {"principal": "alice", "roles": ["actor"]},
    ALICE_OWNER: {"principal": "alice", "roles": ["owner"]},
    BOB_OWNER: {"principal": "bob", "roles": ["owner"]},
    CAROL_AUTH: {"principal": "carol", "roles": ["authority", "verifier", "broker", "operator"]},
    VIEWER: {"principal": "viewer", "roles": ["viewer"]},
}


def hashed(*names):
    return {hashlib.sha256(t.encode()).hexdigest(): dict(TOKENS[t]) for t in names}


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def proposal(tx):
    return {
        "target_id": "shop/api",
        "transaction_id": tx,
        "artifact_base64": base64.b64encode(artifact(2)).decode(),
        "intent": "Principal binding control",
        "expect": {"primary": 2},
    }


# ----- finding 1: alias across tokens -------------------------------------------------------


def test_root_probe_same_principal_two_tokens_is_refused_in_independent_mode():
    """Root's executed probe (opus-principal-alias-probe.json): must now be refused."""
    credentials = hashed(ALICE_ACTOR, ALICE_OWNER)
    validate_credentials(credentials)  # default mode: structurally fine, still accepted
    with pytest.raises(ClosureError) as info:
        validate_credentials(credentials, "independent")
    assert info.value.code == "APPROVAL_SEPARATION_VIOLATED"
    assert "alice" in str(info.value)


def test_alias_is_refused_at_startup_and_locks_on_live_reload(world, tmp_path):
    deployment, pin, _ = world
    with pytest.raises(ClosureError) as info:
        ApiServer(
            ("127.0.0.1", 0),
            Runtime(deployment, pin),
            hashed(ALICE_ACTOR, ALICE_OWNER),
            approval_mode="independent",
        )
    assert info.value.code == "APPROVAL_SEPARATION_VIOLATED"
    directory = tmp_path / "creds"
    directory.mkdir()
    path = directory / "credentials.json"
    path.write_text(json.dumps(hashed(ALICE_ACTOR, BOB_OWNER)))
    server = serve(
        ApiServer(
            ("127.0.0.1", 0),
            Runtime(deployment, pin),
            load_credentials(directory),
            approval_mode="independent",
        )
    )
    try:
        port = server.server_address[1]
        assert call(port, "GET", "/api/v1/whoami", token=ALICE_ACTOR)[0] == 200
        path.write_text(json.dumps(hashed(ALICE_ACTOR, ALICE_OWNER, BOB_OWNER)))  # alias added later
        for token in (ALICE_ACTOR, ALICE_OWNER, BOB_OWNER):
            assert call(port, "GET", "/api/v1/whoami", token=token) == (401, {"error": "UNAUTHORIZED"})
        path.write_text(json.dumps(hashed(ALICE_ACTOR, BOB_OWNER)))
        assert call(port, "GET", "/api/v1/whoami", token=BOB_OWNER)[0] == 200
    finally:
        server.shutdown()
        server.server_close()


# ----- finding 2: sequential re-enrollment ----------------------------------------------------


@pytest.fixture
def rotating(world, tmp_path):
    deployment, pin, _ = world
    directory = tmp_path / "creds"
    directory.mkdir()
    path = directory / "credentials.json"
    path.write_text(json.dumps(hashed(ALICE_ACTOR, BOB_OWNER, CAROL_AUTH, VIEWER)))
    runtime = Runtime(deployment, pin)
    server = serve(
        ApiServer(("127.0.0.1", 0), runtime, load_credentials(directory), approval_mode="independent")
    )
    yield server.server_address[1], path, runtime
    server.shutdown()
    server.server_close()


def test_proposer_cannot_approve_after_revoke_and_owner_reenrollment(rotating):
    port, path, _ = rotating
    assert call(port, "POST", "/api/v1/transactions", proposal("rot-1"), ALICE_ACTOR)[0] == 201
    status, view = call(port, "GET", "/api/v1/transactions/rot-1", token=VIEWER)
    assert status == 200 and view["proposed_by"] == "alice" and view["approved_by"] is None, view
    # Revoke alice's actor token, re-enroll alice owner-only: a valid snapshot at this instant.
    path.write_text(json.dumps(hashed(ALICE_OWNER, BOB_OWNER, CAROL_AUTH, VIEWER)))
    assert (
        call(port, "GET", "/api/v1/whoami", token=ALICE_OWNER)[1]["approval_mode"] == "independent-approval"
    )
    status, value = call(port, "POST", "/api/v1/transactions/rot-1/approve", {}, ALICE_OWNER)
    assert (status, value["error"]) == (403, "APPROVAL_SEPARATION_REQUIRED"), value
    status, view = call(port, "GET", "/api/v1/transactions/rot-1", token=VIEWER)
    assert view["state"] == "PROPOSED" and view["approved"] is False and view["approved_by"] is None
    # A different principal approves; attribution is recorded.
    status, value = call(port, "POST", "/api/v1/transactions/rot-1/approve", {}, BOB_OWNER)
    assert status == 200 and value["state"] == "APPROVED", value
    assert value["proposed_by"] == "alice" and value["approved_by"] == "bob"


def test_legacy_transaction_without_author_binding_is_refused_in_independent_mode(rotating):
    """A transaction proposed outside the API (CLI/legacy) has no bound proposer: fail closed."""
    port, _, runtime = rotating
    runtime.propose("shop/api", "legacy-1", artifact(2), intent="legacy", expect={"primary": 2})
    status, value = call(port, "POST", "/api/v1/transactions/legacy-1/approve", {}, BOB_OWNER)
    assert (status, value["error"]) == (409, "AUTHOR_BINDING_MISSING"), value
    assert call(port, "GET", "/api/v1/transactions/legacy-1", token=VIEWER)[1]["state"] == "PROPOSED"


def test_single_operator_mode_records_attribution_but_does_not_refuse(world, tmp_path):
    deployment, pin, _ = world
    directory = tmp_path / "creds"
    directory.mkdir()
    path = directory / "credentials.json"
    path.write_text(json.dumps(hashed(ALICE_ACTOR, BOB_OWNER, VIEWER)))
    runtime = Runtime(deployment, pin)
    server = serve(ApiServer(("127.0.0.1", 0), runtime, load_credentials(directory)))
    try:
        port = server.server_address[1]
        assert call(port, "POST", "/api/v1/transactions", proposal("admin-1"), ALICE_ACTOR)[0] == 201
        path.write_text(json.dumps(hashed(ALICE_OWNER, BOB_OWNER, VIEWER)))
        status, value = call(port, "POST", "/api/v1/transactions/admin-1/approve", {}, ALICE_OWNER)
        assert status == 200 and value["state"] == "APPROVED", value
        assert value["proposed_by"] == "alice" and value["approved_by"] == "alice"
        # Legacy transactions remain approvable in the default mode.
        runtime.propose("shop/api", "admin-legacy", artifact(2), intent="legacy", expect={"primary": 2})
        assert call(port, "POST", "/api/v1/transactions/admin-legacy/approve", {}, BOB_OWNER)[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_custody_enforces_binding_under_its_own_lock(world):
    """The refusal lives in custody, not only in the gateway: a direct runtime caller gets it too."""
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose(
        "shop/api", "direct-1", artifact(2), intent="direct", expect={"primary": 2}, proposed_by="alice"
    )
    with pytest.raises(ClosureError) as info:
        runtime.approve("direct-1", approved_by="alice", require_independent=True)
    assert info.value.code == "APPROVAL_SEPARATION_REQUIRED"
    assert runtime.status("direct-1")["state"] == "PROPOSED"
    with pytest.raises(ClosureError) as info:
        runtime.approve("direct-1", approved_by=None, require_independent=True)
    assert info.value.code == "APPROVAL_SEPARATION_REQUIRED"
    assert runtime.approve("direct-1", approved_by="bob", require_independent=True)["approved_by"] == "bob"
    # Attribution is persisted with the transaction, not held in process memory.
    again = Runtime(deployment, pin)
    view = again.status("direct-1")
    assert (view["proposed_by"], view["approved_by"]) == ("alice", "bob")
