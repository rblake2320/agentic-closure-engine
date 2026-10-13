"""Independent approval mode: no credential may both author and approve (G1 of the 0.3.1 review).

Real API server, real runtime, real reference target, real credential files. Default mode is
unchanged (``single-operator``). In ``independent`` mode the gateway refuses, fail closed, any
credential that holds both ``actor`` and ``owner`` roles: at startup, on live reload, and again
at the route if a principal ever reaches it another way.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time

import pytest
from test_runtime_api import call
from test_runtime_e2e import artifact
from test_runtime_e2e import world as world  # noqa:F401

from closure_engine.protocol import ClosureError
from closure_engine.runtime import Runtime
from closure_engine.runtime.api import ApiServer, check_separation

ADMIN = "sep-admin-0123456789abcdef0123456789"
ACTOR = "sep-actor-0123456789abcdef0123456789"
OWNER = "sep-owner-0123456789abcdef0123456789"
AUTHORITY = "sep-authority-0123456789abcdef01234567"
VIEWER = "sep-viewer-0123456789abcdef0123456789"
SEPARATED = {
    ACTOR: {"principal": "author-a", "roles": ["actor"]},
    OWNER: {"principal": "approver-b", "roles": ["owner"]},
    AUTHORITY: {"principal": "authority-c", "roles": ["authority", "verifier", "broker", "operator"]},
    VIEWER: {"principal": "auditor-d", "roles": ["viewer"]},
}
MIXED = {
    ADMIN: {
        "principal": "single-admin",
        "roles": ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"],
    }
}


def hashed(tokens):
    return {hashlib.sha256(t.encode()).hexdigest(): dict(p) for t, p in tokens.items()}


def serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def independent_api(world):
    deployment, pin, _ = world
    server = serve(
        ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), hashed(SEPARATED), approval_mode="independent")
    )
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def proposal(tx):
    return {
        "target_id": "shop/api",
        "transaction_id": tx,
        "artifact_base64": base64.b64encode(artifact(2)).decode(),
        "intent": "Independent approval control",
        "expect": {"primary": 2},
    }


def test_default_mode_is_unchanged_and_mixed_credentials_still_load(world):
    deployment, pin, _ = world
    server = serve(ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), hashed({**SEPARATED, **MIXED})))
    try:
        port = server.server_address[1]
        status, value = call(port, "GET", "/api/v1/whoami", token=ADMIN)
        assert (status, value["approval_mode"]) == (200, "single-operator-administration")
        status, value = call(port, "GET", "/api/v1/whoami", token=OWNER)
        assert (status, value["approval_mode"]) == (200, "role-scoped")
    finally:
        server.shutdown()
        server.server_close()


def test_independent_mode_refuses_mixed_credentials_at_startup(world):
    deployment, pin, _ = world
    with pytest.raises(ClosureError) as info:
        ApiServer(
            ("127.0.0.1", 0),
            Runtime(deployment, pin),
            hashed({**SEPARATED, **MIXED}),
            approval_mode="independent",
        )
    assert info.value.code == "APPROVAL_SEPARATION_VIOLATED"
    assert "single-admin" in str(info.value)


def test_unknown_mode_is_refused(world):
    deployment, pin, _ = world
    with pytest.raises(ClosureError) as info:
        ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), hashed(SEPARATED), approval_mode="trust-me")
    assert info.value.code == "APPROVAL_MODE_INVALID"


def test_independent_mode_discloses_itself_and_keeps_author_and_approver_apart(independent_api):
    port = independent_api
    for token in SEPARATED:
        status, value = call(port, "GET", "/api/v1/whoami", token=token)
        assert status == 200 and value["approval_mode"] == "independent-approval", value
        assert value["roles"] == SEPARATED[token]["roles"]
    # The approver cannot author; the author cannot approve.
    assert call(port, "POST", "/api/v1/transactions", proposal("sep-1"), OWNER)[0] == 403
    assert call(port, "POST", "/api/v1/transactions", proposal("sep-1"), ACTOR)[0] == 201
    status, value = call(port, "POST", "/api/v1/transactions/sep-1/approve", {}, ACTOR)
    assert (status, value["error"]) == (403, "ROLE_REQUIRED")
    status, value = call(port, "POST", "/api/v1/transactions/sep-1/approve", {}, OWNER)
    assert status == 200 and value["state"] == "APPROVED", value
    # The approval is signed by the owner key and the proposal by the actor key: two principals,
    # two keys, recorded in the contract view.
    status, value = call(port, "GET", "/api/v1/transactions/sep-1/contract", token=VIEWER)
    assert status == 200 and value["approval"]["payload"]["purpose"] == "approval", value


def test_live_reload_of_a_mixed_credential_fails_closed_then_recovers(world, tmp_path):
    deployment, pin, _ = world
    directory = tmp_path / "creds"
    directory.mkdir()
    path = directory / "credentials.json"
    path.write_text(json.dumps(hashed(SEPARATED)))
    from closure_engine.runtime.api import load_credentials

    source = load_credentials(directory)
    server = serve(ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), source, approval_mode="independent"))
    try:
        port = server.server_address[1]
        assert call(port, "GET", "/api/v1/whoami", token=OWNER)[0] == 200
        # An operator (or an attacker with write access to the mount) adds a mixed credential.
        path.write_text(json.dumps(hashed({**SEPARATED, **MIXED})))
        for token in (ADMIN, OWNER, ACTOR, VIEWER):
            status, value = call(port, "GET", "/api/v1/whoami", token=token)
            assert (status, value) == (401, {"error": "UNAUTHORIZED"}), (token, status, value)
        # Removing the violation restores service without a restart; nothing was signed meanwhile.
        path.write_text(json.dumps(hashed(SEPARATED)))
        assert call(port, "GET", "/api/v1/whoami", token=OWNER)[0] == 200
        assert call(port, "GET", "/api/v1/transactions/never-proposed", token=VIEWER)[0] == 404
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "roles, action, allowed",
    [
        (["actor"], "approve", False),
        (["actor"], "accept", False),
        (["owner"], "propose", False),
        (["owner"], "recover", False),
        (["actor", "owner"], "approve", False),
        (["actor", "owner"], "propose", False),
        (["owner"], "approve", True),
        (["actor"], "propose", True),
        (["authority"], "close", True),
        (["actor", "owner"], "close", True),
    ],
)
def test_route_guard_is_defence_in_depth(roles, action, allowed):
    principal = {"principal": "p", "roles": roles}
    if allowed:
        check_separation("independent", principal, action)
    else:
        with pytest.raises(ClosureError) as info:
            check_separation("independent", principal, action)
        assert info.value.code == "APPROVAL_SEPARATION_REQUIRED"
    check_separation("single-operator", principal, action)  # never raises in the default mode


def test_route_guard_returns_403_over_http(world):
    """A principal that bypasses credential validation still cannot cross the line."""
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    server = ApiServer(("127.0.0.1", 0), runtime, hashed(SEPARATED), approval_mode="independent")
    mixed = {"principal": "smuggled", "roles": ["actor", "owner"]}
    server.credentials.principal = lambda token: mixed if token == ADMIN else None
    serve(server)
    try:
        port = server.server_address[1]
        status, value = call(port, "POST", "/api/v1/transactions", proposal("sep-2"), ADMIN)
        assert (status, value["error"]) == (403, "APPROVAL_SEPARATION_REQUIRED"), value
        assert call(port, "GET", "/api/v1/transactions/sep-2", token=ADMIN)[0] == 404
    finally:
        server.shutdown()
        server.server_close()


def test_console_discloses_independent_mode():
    from importlib.resources import files

    script = files("closure_engine").joinpath("web/closure.js").read_text(encoding="utf-8")
    assert 'identity.approval_mode === "independent-approval"' in script
    assert "Independent approval enforced: no credential may both author and approve." in script


def test_cli_api_serve_accepts_the_mode_and_refuses_mixed_credentials(world, tmp_path):
    deployment, pin, _ = world
    creds = tmp_path / "credentials.json"
    import closure_engine

    src = os.path.dirname(os.path.dirname(os.path.abspath(closure_engine.__file__)))
    env = dict(os.environ, PYTHONPATH=src)
    base = [
        sys.executable,
        "-m",
        "closure_engine",
        "api-serve",
        "--deployment",
        str(deployment.root),
        "--expected-trust-hash",
        pin,
        "--credentials",
        str(creds),
        "--port",
        "0",
        "--approval-mode",
        "independent",
    ]
    creds.write_text(json.dumps(hashed({**SEPARATED, **MIXED})))
    done = subprocess.run(base, capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 2, done.stderr
    assert json.loads(done.stderr.strip().splitlines()[-1])["error"] == "APPROVAL_SEPARATION_VIOLATED"
    creds.write_text(json.dumps(hashed(SEPARATED)))
    process = subprocess.Popen(base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        deadline = time.monotonic() + 30
        line = ""
        while time.monotonic() < deadline and "port" not in line:
            line = process.stdout.readline()
        port = json.loads(line)["port"]
        status, value = call(port, "GET", "/api/v1/whoami", token=OWNER)
        assert (status, value["approval_mode"]) == (200, "independent-approval"), value
    finally:
        process.kill()
        process.wait(timeout=30)
