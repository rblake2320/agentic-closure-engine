"""Two installed releases: safe historical slash subjects remain readable after upgrade."""

import base64
import hashlib
import json
import os
import subprocess
import threading

import pytest
from test_runtime_api import RELEASE, TOKENS, VIEWER, call
from test_runtime_e2e import CHECKS, WINDOW, artifact, free_port

from closure_engine.runtime import Deployment, ReferenceTargetServer, Runtime
from closure_engine.runtime.api import ApiServer

LEGACY_CREATE = r"""
import json, sys, threading, hashlib, base64, http.client, secrets
from pathlib import Path
from closure_engine.runtime.api import ApiServer
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

root, port = Path(sys.argv[1]), int(sys.argv[2])
checks, window = json.loads(sys.argv[3]), json.loads(sys.argv[4])


def artifact(answer):
    return json.dumps(
        {
            "routes": {
                "/answer": {"answer": answer},
                "/config": {"mode": "safe"},
                "/other": {"value": "stable"},
            }
        },
        sort_keys=True,
    ).encode()


dep = Deployment(root / "ace")
for role in ROLES:
    init_identity(dep.role_root(role), role, role + "-legacy")
pin = enroll(dep, [c["id"] for c in checks])["trust_hash"]
target = enroll_target(dep, "shop/api", f"http://127.0.0.1:{port}", checks)
ReferenceTarget.initialize(root / "target", artifact(1), target["deploy_token_sha256"])
server = ReferenceTargetServer(("127.0.0.1", port), root / "target")
threading.Thread(target=server.serve_forever, daemon=True).start()
runtime = Runtime(dep, pin)
token = secrets.token_urlsafe(32)
credentials = {
    hashlib.sha256(token.encode()).hexdigest(): {
        "principal": "legacy-operator",
        "roles": ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"],
    }
}
api = ApiServer(("127.0.0.1", 0), runtime, credentials)
threading.Thread(target=api.serve_forever, daemon=True).start()


def api_call(path, body):
    conn = http.client.HTTPConnection(*api.server_address, timeout=120)
    conn.request(
        "POST",
        "/api/v1" + path,
        json.dumps(body).encode(),
        {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    response = conn.getresponse()
    value = json.loads(response.read())
    conn.close()
    assert response.status in {200, 201}, (response.status, value)
    return value


def propose(tx, value):
    return api_call(
        "/transactions",
        {
            "target_id": "shop/api",
            "transaction_id": tx,
            "artifact_base64": base64.b64encode(artifact(value)).decode(),
            "intent": "Real legacy HTTP proposal",
            "expect": {"primary": value},
            **window,
        },
    )


propose("release/7", 7)
for step in ("approve", "freeze", "baseline"):
    api_call("/transactions/release/7/" + step, {})
assert api_call("/transactions/release/7/run", {})["verdict"] == "PROVEN"
api_call("/transactions/release/7/accept", {})
for tx in ("nested/team/run-1", "release/7/recovery"):
    propose(tx, 8)
api.shutdown()
api.server_close()
files = {
    str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
    for folder in (
        dep.role_root("custodian") / "transactions",
        dep.role_root("custodian") / "records",
        dep.role_root("custodian") / "receipts",
        dep.role_root("custodian") / "evidence",
    )
    for p in folder.rglob("*")
    if p.is_file()
}
server.shutdown()
server.server_close()
print(json.dumps({"pin": pin, "files": files}))
"""


def test_existing_safe_slash_ids_migrate_without_mutating_metadata_or_evidence(tmp_path):
    legacy = os.environ.get("ACE_LEGACY_PYTHON")
    if not legacy:
        pytest.skip("Set ACE_LEGACY_PYTHON to the hash-verified released e3d3538 interpreter")
    port = free_port()
    phase = subprocess.run(
        [legacy, "-I", "-c", LEGACY_CREATE, str(tmp_path), str(port), json.dumps(CHECKS), json.dumps(WINDOW)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert phase.returncode == 0, phase.stderr
    old = json.loads(phase.stdout.strip().splitlines()[-1])
    dep = Deployment(tmp_path / "ace")
    runtime = Runtime(dep, old["pin"])
    target = ReferenceTargetServer(("127.0.0.1", port), tmp_path / "target")
    credentials = {hashlib.sha256(t.encode()).hexdigest(): p for t, p in TOKENS.items()}
    server = ApiServer(("127.0.0.1", 0), runtime, credentials)
    for endpoint in (target, server):
        threading.Thread(target=endpoint.serve_forever, daemon=True).start()
    try:
        address = server.server_address[1]
        baseline = runtime._client("shop/api").state()
        for tx in ("release/7", "nested/team/run-1", "release/7/recovery"):
            status, value = call(address, "GET", "/api/v1/transactions/" + tx, token=VIEWER)
            assert status == 200 and value["transaction_id"] == tx, (status, value)
            status, value = call(address, "GET", "/api/v1/transactions/" + tx + "/contract", token=VIEWER)
            assert status == 200 and value["contract"]["transaction_id"] == tx, (status, value)
        assert call(address, "GET", "/api/v1/transactions/release/7/closure", token=VIEWER)[0] == 200
        assert call(address, "GET", "/api/v1/transactions/release/7/bundle", token=VIEWER)[0] == 200
        status, value = call(address, "GET", "/api/v1/transactions/release/7/ledger", token=VIEWER)
        assert (status, value["error"]) == (404, "ROUTE_NOT_FOUND")
        for bad in ("release/new", "release/7/../other", "nested/./team"):
            status, value = call(
                address,
                "POST",
                "/api/v1/transactions",
                {
                    "target_id": "shop/api",
                    "transaction_id": bad,
                    "artifact_base64": base64.b64encode(artifact(8)).decode(),
                    "expect": {"primary": 8},
                    "intent": "Must remain rejected",
                },
                RELEASE,
            )
            assert (status, value["error"]) == (400, "INVALID_TRANSACTION_ID")
        assert runtime._client("shop/api").state() == baseline
        for name, expected in old["files"].items():
            assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == expected, name
    finally:
        for endpoint in (server, target):
            endpoint.shutdown()
            endpoint.server_close()
