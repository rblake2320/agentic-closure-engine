"""Installed static release + real signed Runtime, HTTP readback and offline replay.

Every Runtime operation uses a fresh child process. This is a same-host process/persistence
gate, not a claim of distinct-host or operating-identity isolation.
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib import error, request

import pytest

from closure_engine.adapters.static_release import StaticReleaseTarget, default_checks, pack_directory
from closure_engine.protocol import digest
from closure_engine.runtime import ROLES, Deployment, Runtime, enroll, enroll_target, init_identity
from closure_engine.runtime.portable import verify_bundle

WINDOW = {"duration_ms": 3000, "min_samples": 3, "max_clock_skew_ms": 1000, "settle_ms": 2000}
RESULTS = {}


def worker(input_path):
    spec = json.loads(Path(input_path).read_bytes())
    if spec["operation"] == "verify":
        return verify_bundle(json.loads(Path(spec["bundle"]).read_bytes()), spec["pin"])
    runtime = Runtime(spec["deployment"], spec["pin"])
    operation, tx = spec["operation"], spec["tx"]
    if operation == "propose":
        return runtime.propose(
            "customer-static",
            tx,
            Path(spec["artifact"]).read_bytes(),
            intent="Publish owner-approved static release",
            expect=spec["expect"],
            **WINDOW,
        )
    if operation == "export":
        bundle = runtime.export_bundle(tx)
        Path(spec["bundle"]).write_text(json.dumps(bundle), encoding="utf-8")
        return {"bundle_hash": digest(bundle), "packet_hash": digest(runtime.closure(tx))}
    if operation in {
        "approve",
        "freeze",
        "baseline",
        "run",
        "accept",
        "begin_recovery",
        "complete_recovery",
        "status",
    }:
        return getattr(runtime, operation)(tx)
    raise ValueError("Unknown test worker operation")


def call(world, operation, tx, **extra):
    spec = {
        "deployment": str(world["deployment"].root),
        "pin": world["pin"],
        "operation": operation,
        "tx": tx,
        **extra,
    }
    path = world["root"] / f"worker-{operation}-{tx.replace('/', '-')}.json"
    path.write_text(json.dumps(spec))
    result = subprocess.run(
        [sys.executable, "-I", str(Path(__file__).absolute()), "--worker", str(path)],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def get(world, path):
    with request.urlopen(world["url"] + path, timeout=5) as response:
        return response.status, response.read(), response.headers


def release(root, version, page):
    source = root / ("source-" + str(version) + "-" + hashlib.sha256(page).hexdigest()[:8])
    source.mkdir()
    (source / "index.html").write_bytes(page)
    (source / "release.json").write_text(json.dumps({"version": version, "entrypoint": "index.html"}))
    (source / "site.css").write_bytes(b"body { color: #203040; background: white; }")
    out = source.with_suffix(".zip")
    pack_directory(source, out)
    return out


def start_target(world):
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine.adapters.static_release",
            "serve",
            "--root",
            str(world["target_root"]),
            "--port",
            str(world["port"]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(process.communicate())
        try:
            get(world, "/ace/v1/state")
            return process
        except (OSError, error.URLError):
            time.sleep(0.05)
    process.kill()
    raise AssertionError("Real target did not start")


@pytest.fixture
def world(tmp_path):
    deployment = Deployment(tmp_path / "closure")
    checks = default_checks()
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "static-" + role)
    pin = enroll(deployment, [check["id"] for check in checks])["trust_hash"]
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        port = channel.getsockname()[1]
    profile = enroll_target(deployment, "customer-static", f"http://127.0.0.1:{port}", checks)
    protected = tmp_path / "operator-policy"
    protected.mkdir()
    (protected / "access.json").write_bytes(b'{"policy":"broker-only"}\n')
    (protected / "retention.json").write_bytes(b'{"policy":"retain-history"}\n')
    original = release(tmp_path, 1, b"<!doctype html><title>Customer portal</title><h1>Original release</h1>")
    target_root = tmp_path / "real-static-target"
    StaticReleaseTarget.initialize(
        target_root, original.read_bytes(), profile["deploy_token_sha256"], protected
    )
    value = {
        "root": tmp_path,
        "deployment": deployment,
        "pin": pin,
        "target_root": target_root,
        "original": original,
        "port": port,
        "url": f"http://127.0.0.1:{port}",
        "protected": protected,
    }
    process = start_target(value)
    value["process"] = process
    try:
        yield value
    finally:
        value["process"].terminate()
        value["process"].wait(timeout=10)


def prepared(world, tx, artifact, version, content_hash):
    call(
        world,
        "propose",
        tx,
        artifact=str(artifact),
        expect={"site-version": version, "site-content": content_hash},
    )
    for operation in ("approve", "freeze", "baseline"):
        call(world, operation, tx)


def proven_recovery(world, parent, before):
    result = call(world, "begin_recovery", parent)
    child = result["transaction_id"]
    for operation in ("approve", "freeze", "baseline"):
        call(world, operation, child)
    restored = call(world, "run", child)
    assert restored["verdict"] == "PROVEN", restored
    complete = call(world, "complete_recovery", parent)
    assert complete["state"] == "RECOVERED", complete
    assert get(world, "/ace/v1/artifact")[1] == before
    path = world["root"] / (parent + "-proof.json")
    call(world, "export", child, bundle=str(path))
    replay = call(world, "verify", child, bundle=str(path))
    assert replay["closure"]["verdict"] == "PROVEN", replay
    return complete, replay


@pytest.fixture(scope="module", autouse=True)
def receipt():
    yield
    path = os.environ.get("ACE_STATIC_RELEASE_RECEIPT")
    if path:
        Path(path).write_text(json.dumps(RESULTS, indent=2), encoding="utf-8")


def test_customer_static_release_proven_served_and_replayed_after_restart(world):
    page = b"<!doctype html><title>Customer portal</title><h1>Orders published</h1>"
    artifact = release(world["root"], 2, page)
    before = get(world, "/ace/v1/artifact")[1]
    prepared(world, "publish-orders", artifact, 2, digest(page))
    result = call(world, "run", "publish-orders")
    assert result["verdict"] == "PROVEN", result
    assert call(world, "accept", "publish-orders")["state"] == "ACCEPTED"
    assert get(world, "/")[1] == page
    assert get(world, "/site.css")[1].startswith(b"body {")
    assert get(world, "/ace/v1/artifact")[1] == artifact.read_bytes()
    assert get(world, "/")[2]["X-Content-Type-Options"] == "nosniff"
    proof = world["root"] / "publication-proof.json"
    call(world, "export", "publish-orders", bundle=str(proof))
    independent = call(world, "verify", "publish-orders", bundle=str(proof))
    assert independent["closure"]["verdict"] == "PROVEN"
    world["process"].terminate()
    world["process"].wait(timeout=10)
    world["process"] = start_target(world)
    assert get(world, "/")[1] == page
    assert call(world, "status", "publish-orders")["state"] == "ACCEPTED"
    RESULTS["customer_publication"] = {
        "verdict": result["verdict"],
        "all_checks": result["checks"],
        "original_hash": digest(before),
        "published_hash": digest(artifact.read_bytes()),
        "served_page_hash": digest(get(world, "/")[1]),
        "independent_replay": independent["closure"]["verdict"],
        "restart_state": "ACCEPTED",
    }


def test_wrong_actual_static_bytes_disproven_and_exact_original_zip_recovered(world):
    before = get(world, "/ace/v1/artifact")[1]
    intended = b"<h1>Approved customer orders</h1>"
    wrong = b"<h1>Wrong customer orders</h1>"
    artifact = release(world["root"], 2, wrong)
    prepared(world, "wrong-orders", artifact, 2, digest(intended))
    result = call(world, "run", "wrong-orders")
    assert result["deployment"]["receipt"] == "EXECUTED"
    assert get(world, "/")[1] == wrong
    assert result["verdict"] == "DISPROVEN" and result["checks"]["site-content"] == "FAIL"
    done, _ = proven_recovery(world, "wrong-orders", before)
    assert get(world, "/")[1].find(b"Original release") > 0
    RESULTS["wrong_content"] = {
        "verdict": result["verdict"],
        "checks": result["checks"],
        "recovery": done["state"],
        "restored_exact_zip_hash": digest(before),
    }


def test_external_operator_resource_mutation_fails_invariant_then_verified_recovery(world):
    before = get(world, "/ace/v1/artifact")[1]
    policy = world["protected"] / "access.json"
    original_policy = policy.read_bytes()
    page = b"<h1>Correct orders but broken access policy</h1>"
    artifact = release(world["root"], 2, page)
    prepared(world, "damaged-policy", artifact, 2, digest(page))
    # Authorized test operator changes the real protected resource after verified baseline;
    # this is a real reachable failure, not an invariant that can never fail.
    policy.write_bytes(b'{"policy":"public-deploy"}\n')
    assert json.loads(get(world, "/protected/access")[1])["policy"] == "public-deploy"
    result = call(world, "run", "damaged-policy")
    assert result["checks"]["site-content"] == "PASS"
    assert result["verdict"] == "DISPROVEN" and result["checks"]["protected-access"] == "FAIL"
    policy.write_bytes(original_policy)
    done, _ = proven_recovery(world, "damaged-policy", before)
    assert get(world, "/protected/access")[1] == original_policy
    RESULTS["protected_resource"] = {
        "verdict": result["verdict"],
        "checks": result["checks"],
        "recovery": done["state"],
        "exact_policy_restored": True,
        "exact_zip_restored": True,
    }


def test_actual_http_auth_preconditions_no_secret_echo_and_archive_denials(world):
    original = get(world, "/ace/v1/artifact")[1]
    token = world["deployment"].target_token_path("customer-static").read_bytes().decode()
    url = world["url"] + "/ace/v1/artifact"
    cases = [(None, original, 401, "unauthorized"), (token, b"bad ZIP", 400, "badzip")]
    for credential, raw, expected, intent in cases:
        headers = {"If-Match": digest(original), "X-ACE-Intent": intent}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        req = request.Request(url, data=raw, method="PUT", headers=headers)
        with pytest.raises(error.HTTPError) as failure:
            request.urlopen(req, timeout=5)
        assert failure.value.code == expected
        assert token.encode() not in failure.value.read()
    headers = {"Authorization": "Bearer " + token, "If-Match": digest(b"stale"), "X-ACE-Intent": "stale"}
    with pytest.raises(error.HTTPError) as failure:
        request.urlopen(request.Request(url, data=original, method="PUT", headers=headers), timeout=5)
    assert failure.value.code == 412
    assert get(world, "/ace/v1/artifact")[1] == original
    for path in ("/../config.json", "/%2e%2e/config.json", "/ace/v1/config"):
        with pytest.raises(error.HTTPError):
            get(world, path)


@pytest.mark.parametrize(
    "duplicates", ["Authorization", "Host", "Content-Length", "If-Match", "X-ACE-Intent", "Transfer-Encoding"]
)
def test_http_ambiguous_headers_refused_without_side_effect(world, duplicates):
    original = get(world, "/ace/v1/artifact")[1]
    token = world["deployment"].target_token_path("customer-static").read_bytes().decode()
    headers = {
        "Host": f"127.0.0.1:{world['port']}",
        "Authorization": "Bearer " + token,
        "If-Match": digest(original),
        "X-ACE-Intent": "ambiguous",
        "Content-Length": str(len(original)),
    }
    lines = ["PUT /ace/v1/artifact HTTP/1.1", *(f"{key}: {value}" for key, value in headers.items())]
    lines.append(
        "Transfer-Encoding: chunked"
        if duplicates == "Transfer-Encoding"
        else f"{duplicates}: {headers[duplicates]}"
    )
    with socket.create_connection(("127.0.0.1", world["port"]), timeout=5) as channel:
        channel.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + original)
        raw = channel.recv(8192)
    assert raw.startswith((b"HTTP/1.0 400", b"HTTP/1.0 401")), raw[:100]
    assert get(world, "/ace/v1/artifact")[1] == original


def test_full_two_megabyte_upload_gets_json_413_and_no_change(world):
    original = get(world, "/ace/v1/artifact")[1]
    token = world["deployment"].target_token_path("customer-static").read_bytes().decode()
    req = request.Request(
        world["url"] + "/ace/v1/artifact",
        data=b"x" * (2 * 1024 * 1024),
        method="PUT",
        headers={
            "Authorization": "Bearer " + token,
            "If-Match": digest(original),
            "X-ACE-Intent": "oversized",
        },
    )
    with pytest.raises(error.HTTPError) as failure:
        request.urlopen(req, timeout=5)
    assert failure.value.code == 413
    assert json.loads(failure.value.read())["limit_bytes"] == 524288
    assert get(world, "/ace/v1/artifact")[1] == original


def test_actual_header_trickle_reaches_whole_connection_deadline(world):
    started = time.monotonic()
    closed = False
    with socket.create_connection(("127.0.0.1", world["port"]), timeout=3) as channel:
        channel.settimeout(0.1)
        channel.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{world['port']}\r\nX-Trickle: ".encode())
        # Another actual client remains usable while the hostile header is unfinished.
        assert get(world, "/release-status")[0] == 200
        while time.monotonic() - started < 12:
            try:
                channel.sendall(b"a")
                if channel.recv(1) == b"":
                    closed = True
                    break
            except socket.timeout:
                continue
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                closed = True
                break
    elapsed = time.monotonic() - started
    assert closed and 9 <= elapsed <= 11, elapsed
    assert get(world, "/release-status")[0] == 200
    RESULTS["header_deadline"] = {
        "elapsed_seconds": elapsed,
        "closed": closed,
        "parallel_and_followup_health": 200,
    }


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--worker":
    print(json.dumps(worker(sys.argv[2])))
