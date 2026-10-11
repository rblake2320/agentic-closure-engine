"""Whole product path through the shipped CLI only: separate processes, real reference target
service, persistent keys, independent verification. No repository scripts or in-memory keys."""

import json
import socket
import subprocess
import sys
import time

import pytest

CHECKS = [
    {
        "id": "primary",
        "kind": "primary",
        "phase": "instant",
        "mandatory": True,
        "probe": {
            "type": "http-json",
            "path": "/answer",
            "pointer": "/answer",
            "artifact_pointer": "/routes/~1answer/answer",
        },
    },
    {
        "id": "protected-config",
        "kind": "invariant",
        "phase": "window",
        "mandatory": True,
        "probe": {"type": "http-unchanged", "path": "/config"},
    },
    {
        "id": "protected-other",
        "kind": "invariant",
        "phase": "window",
        "mandatory": True,
        "probe": {"type": "http-unchanged", "path": "/other"},
    },
    {
        "id": "deployment",
        "kind": "deployment",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "active-artifact"},
    },
    {
        "id": "stage",
        "kind": "stage",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "artifact-bytes"},
    },
    {
        "id": "baseline",
        "kind": "baseline",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "baseline-custody"},
    },
]
ROLES = ("actor", "owner", "broker", "verifier", "authority", "custodian")


def ace(*args, ok=True):
    result = subprocess.run(
        [sys.executable, "-I", "-m", "closure_engine", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if ok:
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    return result


def artifact(path, answer, other="stable"):
    routes = {"/answer": {"answer": answer}, "/config": {"mode": "safe"}, "/other": {"value": other}}
    path.write_text(json.dumps({"routes": routes}, sort_keys=True))
    return path


@pytest.fixture
def product(tmp_path):
    dep = tmp_path / "ace"
    stdout = []
    for role in ROLES:
        stdout.append(
            json.dumps(ace("init", "--deployment", dep, "--role", role, "--issuer", role + "-prod"))
        )
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    (tmp_path / "checks.json").write_text(json.dumps(CHECKS))
    target = ace(
        "target-enroll",
        "--deployment",
        dep,
        "--target-id",
        "shop/api",
        "--base-url",
        f"http://127.0.0.1:{port}",
        "--checks",
        tmp_path / "checks.json",
    )
    pin = ace("enroll", "--deployment", dep, *sum((["--check", c["id"]] for c in CHECKS), []))["trust_hash"]
    ace(
        "target-init",
        "--state-dir",
        tmp_path / "target",
        "--artifact",
        artifact(tmp_path / "v1.json", 1),
        "--token-sha256",
        target["deploy_token_sha256"],
    )
    server = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine",
            "target-serve",
            "--state-dir",
            tmp_path / "target",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert json.loads(server.stdout.readline())["port"] == port
    yield dep, pin, tmp_path, stdout
    server.terminate()
    server.wait(timeout=10)


def tx(dep, pin, action, transaction, *extra):
    return ace(
        "tx", action, "--deployment", dep, "--expected-trust-hash", pin, "--transaction", transaction, *extra
    )


def test_cli_lifecycle_is_proven_and_independently_verifiable(product):
    dep, pin, tmp, stdout = product
    t = "release-2026-10-11"
    tx(
        dep,
        pin,
        "propose",
        t,
        "--target",
        "shop/api",
        "--artifact",
        artifact(tmp / "v2.json", 2),
        "--intent",
        "Raise the answer",
        "--duration-ms",
        "3000",
        "--skew-ms",
        "1000",
        "--settle-ms",
        "1500",
    )
    for action in ("approve", "freeze", "baseline"):
        tx(dep, pin, action, t)
    closed = tx(dep, pin, "run", t)
    assert closed["deployment"]["receipt"] == "EXECUTED"
    assert closed["verdict"] == "PROVEN", closed
    assert tx(dep, pin, "accept", t)["state"] == "ACCEPTED"

    # Independent verification with only public material and the operator pin.
    custody = dep / "custodian"
    ledger = ace(
        "verify-ledger",
        "--ledger",
        custody / "ledger.sqlite",
        "--trust",
        dep / "operator" / "trust.json",
        "--expected-trust-hash",
        pin,
        "--store",
        custody / "evidence",
        "--checkpoint",
        custody / "checkpoint.json",
        "--transaction",
        t,
    )
    assert ledger["state"] == "ACCEPTED"
    tx(dep, pin, "bundle", t, "--output", tmp / "bundle.json")
    status = tx(dep, pin, "status", t)
    packet = json.loads(next((custody / "transactions").glob("*.json")).read_bytes())["verdict_packet"]
    evaluated = ace(
        "evaluate-run",
        "--bundle",
        tmp / "bundle.json",
        "--trust",
        dep / "operator" / "trust.json",
        "--expected-trust-hash",
        pin,
        "--store",
        custody / "evidence",
        "--at",
        packet["payload"]["body"]["evaluated_at"],
        "--require-proven",
    )
    assert evaluated["verdict"] == "PROVEN" and evaluated["mode"] == "runtime"
    assert status["packets"][-1].startswith("sha256:")
    # Private keys never reached stdout; keys persisted and were reused across processes.
    for role in ROLES:
        pem = (dep / role / "identity.key").read_text()
        assert all(pem not in line for line in stdout)
    assert ace("reconcile", "--deployment", dep, "--expected-trust-hash", pin) == {"reconciled": []}


def test_runtime_commands_require_pin_and_reject_time_arguments(product):
    dep, pin, _, _ = product
    missing = ace("status", "--deployment", dep, "--expected-trust-hash", "", ok=False)
    assert missing.returncode == 2 and "TRUST_ANCHOR_REQUIRED" in missing.stderr
    wrong = ace("status", "--deployment", dep, "--expected-trust-hash", "sha256:" + "1" * 64, ok=False)
    assert wrong.returncode == 2 and "TRUST_ANCHOR_MISMATCH" in wrong.stderr
    clock = ace(
        "tx",
        "close",
        "--deployment",
        dep,
        "--expected-trust-hash",
        pin,
        "--transaction",
        "x",
        "--at",
        "2026-01-01T00:00:00Z",
        ok=False,
    )
    assert clock.returncode == 2 and "unrecognized arguments: --at" in clock.stderr
    again = ace("init", "--deployment", dep, "--role", "owner", "--issuer", "owner-prod", ok=False)
    assert again.returncode == 2 and "IDENTITY_ALREADY_EXISTS" in again.stderr


def test_missing_deployment_is_not_created(tmp_path):
    result = ace(
        "status", "--deployment", tmp_path / "nope", "--expected-trust-hash", "sha256:" + "0" * 64, ok=False
    )
    assert result.returncode == 2 and "DEPLOYMENT_MISSING" in result.stderr
    assert not (tmp_path / "nope").exists()
    time.sleep(0)
