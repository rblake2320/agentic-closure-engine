"""Owned Linux producer for verify_multihost.py. Never copies private role/leaf keys out.

All work is below one new operator-selected ace-g3-* directory. This is administrative
Runtime execution, not a claim of per-role OS isolation. The gateway grants only viewer.
"""

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path
from urllib import request

from closure_engine.adapters.static_release import StaticReleaseTarget, default_checks, pack_directory
from closure_engine.protocol import digest
from closure_engine.runtime import ROLES, Deployment, Runtime, enroll, enroll_target, init_identity


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding="utf-8")


def guard(root):
    root = Path(root).resolve()
    if not root.is_dir() or root.parent != Path.home().resolve() or not root.name.startswith("ace-g3-"):
        raise ValueError("REMOTE_ROOT_SCOPE_REFUSED")
    return root


def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_certificate(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    tls = root / "tls"
    tls.mkdir(mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    private_write(
        tls / "server.key",
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACE private G3 producer")]))
        .sign(key, hashes.SHA256())
    )
    private_write(tls / "server.csr", csr.public_bytes(serialization.Encoding.PEM))
    return {
        "csr": str(tls / "server.csr"),
        "leaf_key_stays_remote": True,
        "machine": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


def start_ticks(pid):
    return (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]


def spawn(root, kind, command):
    registry = root / "processes.json"
    records = json.loads(registry.read_bytes()) if registry.exists() else {}
    if kind in records:
        raise ValueError("PROCESS_KIND_ALREADY_REGISTERED")
    with (root / (kind + ".log")).open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True, cwd=root)
    time.sleep(0.15)
    if process.poll() is not None:
        raise ValueError("OWNED_PROCESS_START_FAILED: " + kind)
    records[kind] = {
        "pid": process.pid,
        "start_ticks": start_ticks(process.pid),
        "command": command,
        "stopped": False,
    }
    write(registry, records)
    return process.pid


def stop(root, selected):
    registry = root / "processes.json"
    if not registry.exists():
        return {"stopped": [], "not_started": True}
    records = json.loads(registry.read_bytes())
    results = []
    for kind, record in records.items():
        if selected != "all" and kind != selected:
            continue
        pid = record["pid"]
        proc = Path("/proc") / str(pid)
        if record["stopped"] or not proc.exists():
            record["stopped"] = True
            results.append({"kind": kind, "pid": pid, "status": "ALREADY_STOPPED"})
            continue
        command = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        if (
            start_ticks(pid) != record["start_ticks"]
            or str(root) not in command
            or str(root / "venv/bin/python") not in command
        ):
            raise ValueError("OWNED_PID_GUARD_REFUSED")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while proc.exists() and time.monotonic() < deadline:
            if (proc / "stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
                break
            time.sleep(0.05)
        if proc.exists() and (proc / "stat").read_text().rsplit(")", 1)[1].split()[0] != "Z":
            if start_ticks(pid) != record["start_ticks"]:
                raise ValueError("OWNED_PID_GUARD_REFUSED")
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.1)
        record["stopped"] = True
        results.append({"kind": kind, "pid": pid, "status": "STOPPED"})
    write(registry, records)
    return {"stopped": results}


def publication(root, version, content):
    source = root / ("site-source-" + str(version))
    source.mkdir()
    (source / "index.html").write_bytes(content)
    (source / "release.json").write_text(json.dumps({"version": version, "entrypoint": "index.html"}))
    (source / "site.css").write_bytes(b"body { font-family: sans-serif; color: #182d42; }")
    path = root / ("site-v" + str(version) + ".zip")
    pack_directory(source, path)
    return path.read_bytes()


def run(runtime, tx, raw, expect):
    runtime.propose(
        "customer-static",
        tx,
        raw,
        intent="Publish the owner-approved customer orders page",
        expect=expect,
        duration_ms=5000,
        min_samples=3,
        settle_ms=1500,
        max_clock_skew_ms=1500,
    )
    for action in ("approve", "freeze", "baseline"):
        getattr(runtime, action)(tx)
    return runtime.run(tx)


def produce(root, bind, target_port, gateway_port, expected_wheel_hash):
    from importlib.metadata import version

    wheel = next(root.glob("agentic_closure_engine-*.whl"))
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected_wheel_hash:
        raise ValueError("REMOTE_WHEEL_HASH_MISMATCH")
    deployment = Deployment(root / "authority")
    checks = default_checks()
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "g3-linux-" + role)
    pin = enroll(deployment, [item["id"] for item in checks])["trust_hash"]
    target = enroll_target(deployment, "customer-static", f"http://127.0.0.1:{target_port}", checks)
    policies = root / "operator-policy"
    policies.mkdir()
    (policies / "access.json").write_bytes(b'{"deploy":"broker-only"}\n')
    (policies / "retention.json").write_bytes(b'{"history":"immutable"}\n')
    baseline_page = b"<!doctype html><title>Orders portal</title><h1>Orders release 1</h1>"
    desired_page = b"<!doctype html><title>Orders portal</title><h1>Approved orders release 2</h1>"
    wrong_page = b"<!doctype html><title>Orders portal</title><h1>WRONG orders release 3</h1>"
    baseline, correct, wrong = (
        publication(root, 1, baseline_page),
        publication(root, 2, desired_page),
        publication(root, 3, wrong_page),
    )
    StaticReleaseTarget.initialize(root / "target", baseline, target["deploy_token_sha256"], policies)
    target_pid = spawn(
        root,
        "target",
        [
            str(root / "venv/bin/python"),
            "-I",
            "-m",
            "closure_engine.adapters.static_release",
            "serve",
            "--root",
            str(root / "target"),
            "--port",
            str(target_port),
        ],
    )
    for _ in range(100):
        try:
            with request.urlopen(f"http://127.0.0.1:{target_port}/", timeout=2) as response:
                assert response.read() == baseline_page
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise ValueError("TARGET_STARTUP_TIMEOUT")
    runtime = Runtime(deployment, pin)
    positive = run(
        runtime, "g3-publication", correct, {"site-version": 2, "site-content": digest(desired_page)}
    )
    assert positive["verdict"] == "PROVEN", positive
    accepted = runtime.accept("g3-publication")
    assert accepted["state"] == "ACCEPTED"
    with request.urlopen(f"http://127.0.0.1:{target_port}/", timeout=2) as response:
        assert response.read() == desired_page
    failed = run(
        runtime,
        "g3-wrong-content",
        wrong,
        {"site-version": 3, "site-content": digest(b"OWNER APPROVED RELEASE 3")},
    )
    assert failed["verdict"] == "DISPROVEN" and failed["checks"]["site-content"] == "FAIL"
    assert failed["deployment"]["receipt"] == "EXECUTED"
    child = runtime.begin_recovery("g3-wrong-content")["transaction_id"]
    for action in ("approve", "freeze", "baseline"):
        getattr(runtime, action)(child)
    restored = runtime.run(child)
    assert restored["verdict"] == "PROVEN", restored
    completed = runtime.complete_recovery("g3-wrong-content")
    assert completed["state"] == "RECOVERED"
    with request.urlopen(f"http://127.0.0.1:{target_port}/ace/v1/artifact", timeout=2) as response:
        final_zip = response.read()
    assert final_zip == correct
    with request.urlopen(f"http://127.0.0.1:{target_port}/", timeout=2) as response:
        assert response.read() == desired_page
    public = root / "public"
    public.mkdir()
    (public / "trust.json").write_bytes(deployment.trust_path.read_bytes())
    (public / "trust.pin").write_text(pin)
    write(public / "checkpoint.json", runtime.checkpoint())
    manifest = {"url": f"https://{bind}:{gateway_port}", "target_id": "customer-static", "transactions": {}}
    for tx in ("g3-publication", "g3-wrong-content", child):
        closure = runtime.closure(tx)
        body = closure["packet"]["payload"]["body"]
        manifest["transactions"][tx] = {
            "expected": {
                key: body[key] for key in ("transaction_id", "contract_hash", "artifact_hash", "target_id")
            },
            "verdict": body["verdict"],
        }
    write(public / "manifest.json", manifest)
    issue = subprocess.run(
        [
            str(root / "venv/bin/python"),
            "-I",
            "-m",
            "closure_engine",
            "api-credential",
            "--credentials",
            str(root / "auth"),
            "--principal",
            "windows-public-only-viewer",
            "--role",
            "viewer",
            "--token-out",
            str(root / "viewer.token"),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if issue.returncode:
        raise ValueError("VIEWER_ISSUANCE_FAILED")
    receipt = {
        "machine": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "package_version": version("agentic-closure-engine"),
        "wheel_sha256": expected_wheel_hash,
        "root": str(root),
        "target_pid": target_pid,
        "administration_mode": "all-key Runtime on one Linux operating identity; not OS-role isolation",
        "positive": {
            "state": accepted["state"],
            "verdict": positive["verdict"],
            "checks": positive["checks"],
            "artifact_hash": digest(correct),
            "served_page_hash": digest(desired_page),
        },
        "failure": {
            "verdict": failed["verdict"],
            "checks": failed["checks"],
            "receipt": failed["deployment"]["receipt"],
        },
        "recovery": {
            "child_verdict": restored["verdict"],
            "parent_state": completed["state"],
            "exact_failed_run_baseline_zip_restored": final_zip == correct,
            "restored_zip_hash": digest(final_zip),
        },
        "gateway_roles": ["viewer"],
        "target_initial_zip_hash": digest(baseline),
    }
    write(public / "producer-receipt.json", receipt)
    return receipt


def gateway(root, bind, port, kind="gateway", cert_name="server.crt"):
    pin = (root / "public/trust.pin").read_text().strip()
    return {
        "gateway_pid": spawn(
            root,
            kind,
            [
                str(root / "venv/bin/python"),
                "-I",
                "-m",
                "closure_engine",
                "api-serve",
                "--deployment",
                str(root / "authority"),
                "--expected-trust-hash",
                pin,
                "--credentials",
                str(root / "auth"),
                "--bind",
                bind,
                "--port",
                str(port),
                "--allowed-host",
                f"{bind}:{port}",
                "--tls-cert-file",
                str(root / "tls" / cert_name),
                "--tls-key-file",
                str(root / "tls/server.key"),
            ],
        )
    }


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("csr", "produce", "gateway", "stop"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--bind")
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--port", type=int)
    parser.add_argument("--wheel-sha256")
    parser.add_argument(
        "--kind",
        choices=("target", "gateway", "gateway-controls", "gateway-hostname-negative", "all"),
        default="all",
    )
    parser.add_argument("--cert-name", choices=("server.crt", "wrong-host.crt"), default="server.crt")
    args = parser.parse_args()
    root = guard(args.root)
    if args.phase == "csr":
        value = prepare_certificate(root)
    elif args.phase == "produce":
        value = produce(root, args.bind, args.target_port, args.port, args.wheel_sha256)
    elif args.phase == "gateway":
        value = gateway(
            root, args.bind, args.port, "gateway" if args.kind == "all" else args.kind, args.cert_name
        )
    else:
        value = stop(root, args.kind)
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
