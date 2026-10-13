"""Authenticated loopback API over the real runtime and a real reference target."""

import base64
import hashlib
import http.client
import json
import subprocess
import sys
import threading

import pytest
from test_runtime_e2e import CHECKS, WINDOW, artifact, free_port

from closure_engine.runtime import (
    ROLES,
    Deployment,
    ReferenceTarget,
    ReferenceTargetServer,
    Runtime,
    enroll,
    enroll_target,
    init_identity,
)
from closure_engine.runtime.api import ApiServer

TOKENS = {
    "viewer-token-0123456789abcdef0123456789": {"principal": "auditor", "roles": ["viewer"]},
    "release-token-0123456789abcdef012345678": {
        "principal": "release-manager",
        "roles": ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"],
    },
}


@pytest.fixture
def api(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-api")
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    tport = free_port()
    target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{tport}", CHECKS)
    ReferenceTarget.initialize(tmp_path / "target", artifact(1), target["deploy_token_sha256"])
    tserver = ReferenceTargetServer(("127.0.0.1", tport), tmp_path / "target")
    static = tmp_path / "ui"
    static.mkdir()
    (static / "index.html").write_text("<h1>ACE</h1>")
    (tmp_path / "secret.txt").write_text("outside")
    credentials = {hashlib.sha256(t.encode()).hexdigest(): p for t, p in TOKENS.items()}
    server = ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), credentials, static)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (tserver, server)]
    for thread in threads:
        thread.start()
    yield server.server_address[1]
    for s in (server, tserver):
        s.shutdown()
        s.server_close()


def call(port, method, path, body=None, token=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    sent = {"Host": f"127.0.0.1:{port}", **(headers or {})}
    if token:
        sent["Authorization"] = "Bearer " + token
    raw = None
    if body is not None:
        raw = json.dumps(body).encode()
        sent["Content-Type"] = "application/json"
    conn.request(method, path, body=raw, headers=sent)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    try:
        return response.status, json.loads(data)
    except ValueError:
        return response.status, data


VIEWER, RELEASE = list(TOKENS)


def test_authentication_and_origin_controls(api):
    assert call(api, "GET", "/api/v1/health") == (200, {"service": "ace-runtime", "status": "ok"})
    assert call(api, "GET", "/api/v1/status")[0] == 401
    assert call(api, "GET", "/api/v1/status", token="x" * 40)[0] == 401
    assert call(api, "GET", "/api/v1/status", token=VIEWER, headers={"Host": "evil.example:80"})[0] == 403
    assert (
        call(api, "GET", "/api/v1/status", token=VIEWER, headers={"Origin": "http://evil.example"})[0] == 403
    )
    assert call(api, "GET", "/api/v1/whoami", token=VIEWER) == (
        200,
        dict(TOKENS[VIEWER], approval_mode="role-scoped"),
    )


def test_static_ui_is_same_origin_and_cannot_escape(api):
    assert call(api, "GET", "/")[1] == b"<h1>ACE</h1>"
    assert call(api, "GET", "/../secret.txt")[0] == 404
    assert call(api, "GET", "/%2e%2e/secret.txt")[0] == 404


def test_role_gating_and_no_caller_clock(api):
    body = {
        "target_id": "shop/api",
        "transaction_id": "api-1",
        "artifact_base64": base64.b64encode(artifact(2)).decode(),
        "expect": {"primary": 2},
        "intent": "API change",
    }
    status, value = call(api, "POST", "/api/v1/transactions", body, VIEWER)
    assert (status, value["error"], value["role"]) == (403, "ROLE_REQUIRED", "actor")
    status, value = call(api, "POST", "/api/v1/transactions", dict(body, now="2020-01-01T00:00:00Z"), RELEASE)
    assert (status, value["error"]) == (400, "INVALID_REQUEST")
    status, value = call(
        api, "POST", "/api/v1/transactions/api-1/close", {"at": "2020-01-01T00:00:00Z"}, RELEASE
    )
    assert status in {400, 404}


def test_full_transaction_through_api(api):
    body = {
        "target_id": "shop/api",
        "transaction_id": "api-release-7",
        "artifact_base64": base64.b64encode(artifact(7)).decode(),
        "expect": {"primary": 7},
        "intent": "Release seven",
        "duration_ms": WINDOW["duration_ms"],
        "min_samples": WINDOW["min_samples"],
        "max_clock_skew_ms": WINDOW["max_clock_skew_ms"],
        "settle_ms": WINDOW["settle_ms"],
    }
    assert call(api, "POST", "/api/v1/transactions", body, RELEASE)[0] == 201
    for action in ("approve", "freeze", "baseline"):
        status, value = call(api, "POST", f"/api/v1/transactions/api-release-7/{action}", None, RELEASE)
        assert status == 200, value
    status, result = call(api, "POST", "/api/v1/transactions/api-release-7/run", None, RELEASE)
    assert status == 200 and result["verdict"] == "PROVEN", result
    assert call(api, "POST", "/api/v1/transactions/api-release-7/accept", None, VIEWER)[0] == 403
    assert (
        call(api, "POST", "/api/v1/transactions/api-release-7/accept", None, RELEASE)[1]["state"]
        == "ACCEPTED"
    )
    status, view = call(api, "GET", "/api/v1/transactions/api-release-7", token=VIEWER)
    assert status == 200 and view["state"] == "ACCEPTED"
    status, bundle = call(api, "GET", "/api/v1/transactions/api-release-7/bundle", token=VIEWER)
    assert status == 200 and bundle["mode"] == "runtime"
    assert call(api, "GET", "/api/v1/transactions/nope", token=VIEWER)[0] == 404


def test_api_credential_command_stores_only_hash(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine",
            "api-credential",
            "--credentials",
            tmp_path / "credentials.json",
            "--principal",
            "ui",
            "--role",
            "viewer",
            "--token-out",
            tmp_path / "ui.token",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    token = (tmp_path / "ui.token").read_text()
    assert token not in result.stdout and token not in (tmp_path / "credentials.json").read_text()
    stored = json.loads((tmp_path / "credentials.json").read_text())
    assert stored == {hashlib.sha256(token.encode()).hexdigest(): {"principal": "ui", "roles": ["viewer"]}}


def test_status_lists_staged_proposals_as_unapproved_without_verdict(api):
    body = {
        "target_id": "shop/api",
        "transaction_id": "staged-1",
        "artifact_base64": base64.b64encode(artifact(11)).decode(),
        "expect": {"primary": 11},
        "intent": "Staged only",
    }
    assert call(api, "POST", "/api/v1/transactions", body, RELEASE)[0] == 201
    status, summary = call(api, "GET", "/api/v1/status", token=VIEWER)
    item = next(i for i in summary["items"] if i["transaction_id"] == "staged-1")
    assert status == 200 and item["state"] == "PROPOSED" and item["approved"] is False
    assert item["verdict"] is None and item["technical_packet_hash"] is None
    assert "staged-1" not in summary["transactions"]  # ledger map stays ledger-only
    assert call(api, "POST", "/api/v1/transactions/staged-1/approve", None, RELEASE)[0] == 200
    item = next(
        i
        for i in call(api, "GET", "/api/v1/status", token=VIEWER)[1]["items"]
        if i["transaction_id"] == "staged-1"
    )
    assert item["approved"] is True and item["state"] == "APPROVED" and item["verdict"] is None


def test_packaged_ui_is_used_only_when_shipped():
    from closure_engine.runtime.commands import packaged_ui

    path = packaged_ui()
    assert path is None or (__import__("pathlib").Path(path) / "index.html").is_file()


def test_owner_can_review_exact_draft_contract_before_approval(api):
    body = {
        "target_id": "shop/api",
        "transaction_id": "review-1",
        "artifact_base64": base64.b64encode(artifact(12)).decode(),
        "expect": {"primary": 12},
        "intent": "Reviewable change",
    }
    created = call(api, "POST", "/api/v1/transactions", body, RELEASE)[1]
    status, draft = call(api, "GET", "/api/v1/transactions/review-1/contract", token=VIEWER)
    assert status == 200 and draft["approval"] is None
    assert draft["contract_hash"] == created["contract_hash"]
    contract = draft["contract"]
    assert contract["intent"] == "Reviewable change" and contract["protected_resources"]
    assert {c["id"]: (c["phase"], c["mandatory"]) for c in contract["checks"]}["protected-other"] == (
        "window",
        True,
    )
    assert set(contract["window"]) == {
        "duration_ms",
        "max_gap_ms",
        "min_samples",
        "max_age_ms",
        "max_clock_skew_ms",
    }
    assert call(api, "POST", "/api/v1/transactions/review-1/approve", None, RELEASE)[0] == 200
    approved = call(api, "GET", "/api/v1/transactions/review-1/contract", token=VIEWER)[1]
    assert approved["approval"]["payload"]["body"]["contract_hash"] == draft["contract_hash"]
    assert call(api, "POST", "/api/v1/transactions/review-1/contract", None, RELEASE)[0] == 404
