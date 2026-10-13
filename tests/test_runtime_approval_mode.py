"""Real API controls for explicit administrative approval mode, not certification."""

import base64
import hashlib
import threading

import pytest
from test_runtime_api import call
from test_runtime_e2e import artifact
from test_runtime_e2e import world as world  # noqa:F401

from closure_engine.runtime import Runtime
from closure_engine.runtime.api import ApiServer

TOKENS = {
    "mode-admin-0123456789abcdef0123456789": {
        "principal": "single-admin",
        "roles": ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"],
    },
    "mode-actor-0123456789abcdef0123456789": {"principal": "actor-a", "roles": ["actor"]},
    "mode-owner-0123456789abcdef0123456789": {"principal": "owner-b", "roles": ["owner"]},
    "mode-viewer-0123456789abcdef0123456789": {"principal": "viewer-c", "roles": ["viewer"]},
}


@pytest.fixture
def mode_api(world):
    deployment, pin, _ = world
    credentials = {hashlib.sha256(t.encode()).hexdigest(): dict(p) for t, p in TOKENS.items()}
    server = ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), credentials)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("token", list(TOKENS))
def test_whoami_discloses_mode_without_mutating_roles_or_credentials(mode_api, token):
    before = TOKENS[token]
    expected = (
        "single-operator-administration" if {"actor", "owner"} <= set(before["roles"]) else "role-scoped"
    )
    status, value = call(mode_api, "GET", "/api/v1/whoami", token=token)
    assert status == 200
    assert value == dict(before, approval_mode=expected)
    # Repeated authentication remains valid; metadata must not mutate trusted enrollment.
    assert call(mode_api, "GET", "/api/v1/whoami", token=token) == (status, value)
    assert "approval_mode" not in TOKENS[token]


def test_distinct_actor_and_owner_principals_keep_role_gates(mode_api):
    actor, owner = list(TOKENS)[1:3]
    body = {
        "target_id": "shop/api",
        "transaction_id": "scoped-mode",
        "artifact_base64": base64.b64encode(artifact(2)).decode(),
        "intent": "Separate principal approval",
        "expect": {"primary": 2},
    }
    assert call(mode_api, "POST", "/api/v1/transactions", body, owner)[0] == 403
    assert call(mode_api, "POST", "/api/v1/transactions", body, actor)[0] == 201
    status, value = call(mode_api, "POST", "/api/v1/transactions/scoped-mode/approve", {}, actor)
    assert (status, value["error"], value["role"]) == (403, "ROLE_REQUIRED", "owner")
    status, value = call(mode_api, "POST", "/api/v1/transactions/scoped-mode/approve", {}, owner)
    assert status == 200 and value["state"] == "APPROVED"
    status, value = call(mode_api, "POST", "/api/v1/transactions/scoped-mode/freeze", {}, actor)
    assert (status, value["error"], value["role"]) == (403, "ROLE_REQUIRED", "authority")


def test_shipped_console_discloses_approval_mode_as_plaintext():
    from importlib.resources import files

    html = files("closure_engine").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("closure_engine").joinpath("web/closure.js").read_text(encoding="utf-8")
    assert '<p id="approval-mode" class="hint" aria-live="polite"></p>' in html
    assert "identity.approval_mode" in script
    assert "Single-operator administration; human approval is not independent." in script
    assert "Roles restricted. This session is limited to the roles shown." in script
    assert '$("approval-mode").textContent' in script
