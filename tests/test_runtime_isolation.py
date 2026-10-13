"""Isolated deployment topology, each service a separate process started by the shipped CLI:
custody (custodian key only), five role services (one key each), a keyless operator gateway,
and a real reference target. Proves no process holds two keys and the boundaries are enforced."""

import base64
import hashlib
import http.client
import json
import shutil
import subprocess
import sys
import threading

import pytest
from test_runtime_e2e import CHECKS, WINDOW, artifact, free_port

from closure_engine.runtime import (
    Deployment,
    ReferenceTarget,
    ReferenceTargetServer,
    enroll,
    enroll_target,
)
from closure_engine.runtime.identities import init_identity

SERVICE_ROLES = ("actor", "owner", "authority", "verifier", "broker")


def token(seed):
    return seed + "-" + hashlib.sha256(seed.encode()).hexdigest()[:40]


def write_credentials(directory, entries):
    directory.mkdir(parents=True, exist_ok=True)
    data = {
        hashlib.sha256(t.encode()).hexdigest(): {"principal": p, "roles": r} for t, (p, r) in entries.items()
    }
    (directory / "credentials.json").write_text(json.dumps(data))


def start(*args):
    process = subprocess.Popen(
        [sys.executable, "-I", "-m", "closure_engine", *map(str, args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = process.stdout.readline()
    if not line:
        process.wait(timeout=10)
        raise AssertionError(process.stderr.read())
    return process, json.loads(line)


def call(port, method, path, body=None, bearer=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    raw = None
    if body is not None:
        raw = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=raw, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, json.loads(data) if data else None


@pytest.fixture(scope="module")
def topology(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("isolated")
    services = {name: tmp / "svc" / name / "ace" for name in (*SERVICE_ROLES, "custody")}
    key_role = {**{r: r for r in SERVICE_ROLES}, "custody": "custodian"}
    # Each identity is created inside its own service tree; only public records leave it.
    operator = Deployment(tmp / "operator-workspace")
    for name, root in services.items():
        role = key_role[name]
        init_identity(Deployment(root).role_root(role), role, role + "-iso")
        public = Deployment(root).role_root(role) / "identity.json"
        operator.role_root(role).mkdir(parents=True)
        shutil.copy(public, operator.role_root(role) / "identity.json")
    pin = enroll(operator, [c["id"] for c in CHECKS])["trust_hash"]
    tport = free_port()
    target = enroll_target(operator, "shop/api", f"http://127.0.0.1:{tport}", CHECKS)
    for root in services.values():
        shutil.copytree(operator.role_root("operator"), Deployment(root).role_root("operator"))
    token_file = operator.target_token_path("shop/api")
    broker_targets = Deployment(services["broker"]).role_root("broker") / "targets"
    broker_targets.mkdir(parents=True)
    shutil.copy(token_file, broker_targets / token_file.name)
    ReferenceTarget.initialize(tmp / "target", artifact(1), target["deploy_token_sha256"])
    tserver = ReferenceTargetServer(("127.0.0.1", tport), tmp / "target")
    threading.Thread(target=tserver.serve_forever, daemon=True).start()

    tokens = {name: token("svc-" + name) for name in SERVICE_ROLES}
    gateway_token, user_token, viewer_token = token("gateway"), token("release-user"), token("auditor")
    write_credentials(
        tmp / "creds" / "custody",
        {
            **{tokens[r]: (r + "-service", [r]) for r in SERVICE_ROLES},
            gateway_token: ("gateway", ["operator", "viewer"]),
        },
    )
    for role in SERVICE_ROLES:
        write_credentials(tmp / "creds" / role, {gateway_token: ("gateway", ["operator"])})
    all_roles = ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"]
    write_credentials(
        tmp / "creds" / "gateway",
        {user_token: ("release-user", all_roles), viewer_token: ("auditor", ["viewer"])},
    )
    for name, value in {**tokens, "gateway": gateway_token}.items():
        (tmp / (name + ".token")).write_text(value)

    processes = []
    cport = free_port()
    processes.append(
        start(
            "custody-serve",
            "--deployment",
            services["custody"],
            "--expected-trust-hash",
            pin,
            "--port",
            cport,
            "--credentials",
            tmp / "creds" / "custody",
        )[0]
    )
    ports = {}
    for role in SERVICE_ROLES:
        ports[role] = free_port()
        processes.append(
            start(
                "role-serve",
                "--role",
                role,
                "--deployment",
                services[role],
                "--expected-trust-hash",
                pin,
                "--custody-url",
                f"http://127.0.0.1:{cport}",
                "--custody-token-file",
                tmp / (role + ".token"),
                "--port",
                ports[role],
                "--credentials",
                tmp / "creds" / role,
            )[0]
        )
    config = {
        role: {"url": f"http://127.0.0.1:{ports[role]}", "token_file": str(tmp / "gateway.token")}
        for role in SERVICE_ROLES
    }
    config["custody"] = {"url": f"http://127.0.0.1:{cport}", "token_file": str(tmp / "gateway.token")}
    (tmp / "services.json").write_text(json.dumps(config))
    gport = free_port()
    processes.append(
        start(
            "api-serve",
            "--services",
            tmp / "services.json",
            "--port",
            gport,
            "--credentials",
            tmp / "creds" / "gateway",
        )[0]
    )
    yield {
        "tmp": tmp,
        "pin": pin,
        "services": services,
        "gateway": gport,
        "custody": cport,
        "roles": ports,
        "user": user_token,
        "viewer": viewer_token,
        "tokens": tokens,
        "gateway_token": gateway_token,
    }
    for process in processes:
        process.terminate()
        process.wait(timeout=10)
    tserver.shutdown()
    tserver.server_close()


def gateway_tx(t, tx, body, actions=("approve", "freeze", "baseline")):
    if body is not None:
        status, value = call(t["gateway"], "POST", "/api/v1/transactions", body, t["user"])
        assert status == 201, value
    for action in actions:
        status, value = call(t["gateway"], "POST", f"/api/v1/transactions/{tx}/{action}", None, t["user"])
        assert status == 200, (action, value)
    status, value = call(t["gateway"], "POST", f"/api/v1/transactions/{tx}/run", None, t["user"])
    assert status == 200, value
    return value


def proposal(tx, raw):
    return {
        "target_id": "shop/api",
        "transaction_id": tx,
        "artifact_base64": base64.b64encode(raw).decode(),
        "expect": {"primary": json.loads(raw)["routes"]["/answer"]["answer"]},
        "intent": "isolated release",
        "duration_ms": WINDOW["duration_ms"],
        "min_samples": WINDOW["min_samples"],
        "max_clock_skew_ms": WINDOW["max_clock_skew_ms"],
        "settle_ms": WINDOW["settle_ms"],
    }


def test_no_service_tree_holds_more_than_its_own_key(topology):
    for name, root in topology["services"].items():
        keys = sorted(p.parent.name for p in root.rglob("identity.key"))
        assert keys == ["custodian" if name == "custody" else name], (name, keys)
    gateway_files = list((topology["tmp"] / "creds" / "gateway").rglob("*.key"))
    assert gateway_files == []


def test_isolated_proven_then_disproven_and_recovered(topology):
    t = topology
    result = gateway_tx(t, "iso-good", proposal("iso-good", artifact(2)))
    assert result["verdict"] == "PROVEN", result
    assert (
        call(t["gateway"], "POST", "/api/v1/transactions/iso-good/accept", None, t["user"])[1]["state"]
        == "ACCEPTED"
    )
    bad = gateway_tx(t, "iso-bad", proposal("iso-bad", artifact(3, other="BROKEN")))
    assert bad["verdict"] == "DISPROVEN" and bad["state"] == "RECOVERY_REQUIRED"
    status, value = call(t["gateway"], "POST", "/api/v1/transactions/iso-bad/recover", None, t["user"])
    assert status == 200, value
    child = gateway_tx(t, "iso-bad/recovery", None)
    assert child["verdict"] == "PROVEN", child
    status, value = call(
        t["gateway"], "POST", "/api/v1/transactions/iso-bad/recover-complete", None, t["user"]
    )
    assert status == 200 and value["state"] == "RECOVERED", value


def test_role_services_expose_only_their_own_actions(topology):
    t = topology
    gw = t["gateway_token"]
    assert call(t["roles"]["authority"], "POST", "/role/v1/deploy", {"transaction_id": "x"}, gw)[0] == 404
    assert call(t["roles"]["verifier"], "POST", "/role/v1/approve", {"transaction_id": "x"}, gw)[0] == 404
    assert (
        call(t["roles"]["broker"], "POST", "/role/v1/deploy", {"transaction_id": "x"}, t["viewer"])[0] == 401
    )
    # No route signs a caller-supplied object.
    status, _ = call(
        t["roles"]["owner"], "POST", "/role/v1/approve", {"transaction_id": "x", "approval": {}}, gw
    )
    assert status == 400


def test_custody_enforces_caller_roles_and_host_allow_list(topology):
    t = topology
    verifier = t["tokens"]["verifier"]
    assert (
        call(t["custody"], "POST", "/custody/v1/approval", {"transaction_id": "x", "approval": {}}, verifier)[
            0
        ]
        == 403
    )
    assert (
        call(t["custody"], "POST", "/custody/v1/receipts", {"transaction_id": "x", "receipt": {}}, verifier)[
            0
        ]
        == 403
    )
    assert call(t["custody"], "GET", "/custody/v1/summary", None, verifier, host="evil.example:80")[0] == 403
    assert call(t["custody"], "GET", "/custody/v1/summary", None, "x" * 40)[0] == 401


def test_missing_key_refuses_to_start_role_service(topology):
    t = topology
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine",
            "role-serve",
            "--role",
            "owner",
            "--deployment",
            t["services"]["authority"],
            "--expected-trust-hash",
            t["pin"],
            "--custody-url",
            f"http://127.0.0.1:{t['custody']}",
            "--custody-token-file",
            t["tmp"] / "authority.token",
            "--port",
            str(free_port()),
            "--credentials",
            t["tmp"] / "creds" / "authority",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 2 and "IDENTITY_MISSING" in result.stderr


def test_credential_revocation_is_live(topology):
    t = topology
    assert call(t["gateway"], "GET", "/api/v1/status", None, t["viewer"])[0] == 200
    revoke = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine",
            "api-revoke",
            "--credentials",
            t["tmp"] / "creds" / "gateway",
            "--token-sha256",
            hashlib.sha256(t["viewer"].encode()).hexdigest(),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert revoke.returncode == 0, revoke.stderr
    assert call(t["gateway"], "GET", "/api/v1/status", None, t["viewer"])[0] == 401
    assert call(t["gateway"], "GET", "/api/v1/status", None, t["user"])[0] == 200


def test_gateway_attribution_reaches_custody_through_role_services(topology):
    """Keyless gateway -> actor/owner role services -> custody service: the authenticated gateway
    principal is persisted with the transaction, not a client body field."""
    t = topology
    body = proposal("iso-attr", artifact(7))
    status, value = call(
        t["gateway"], "POST", "/api/v1/transactions", {**body, "proposed_by": "mallory"}, t["user"]
    )
    assert status == 400, value  # the public API refuses caller-selected attribution
    status, value = call(t["gateway"], "POST", "/api/v1/transactions", body, t["user"])
    assert status == 201, value
    status, value = call(t["gateway"], "POST", "/api/v1/transactions/iso-attr/approve", None, t["user"])
    assert status == 200 and value["state"] == "APPROVED", value
    assert (value["proposed_by"], value["approved_by"]) == ("release-user", "release-user")
    status, value = call(t["gateway"], "GET", "/api/v1/transactions/iso-attr", None, t["user"])
    assert status == 200 and (value["proposed_by"], value["approved_by"]) == ("release-user", "release-user")
