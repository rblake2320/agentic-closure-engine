"""Physical Spark2 witness -> Windows custody gate and public-only historical replay.

Requires exact operator-supplied candidate wheel hash and strict known-hosts SSH. Creates
only fresh directories, role keys and one owned TLS witness process. Secrets never appear
in command arguments or reports. Uses the established verify_multihost.py transport/CSR
helpers without changing that controller. This is a bounded real HTTP target run, not an
absolute UTC, independent administrator or production credential-isolation claim.
"""

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
import platform
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib import request

FORBIDDEN_PORTS = {56628, 56629, 56630, 49936}
FORBIDDEN_PID = 14684
EXPECTATIONS = {
    "W01": "Windows runtime and physical Linux aarch64 witness install identical pinned wheel bytes",
    "W02": "Witness signer and TLS leaf private keys stay on Spark2; separate pinned identity via SSH",
    "W03": "Actual target correction PROVEN, owner ACCEPTED, exact admitted events independently witnessed",
    "W04": "Externally supplied wrong witness pin and altered receipt signature fail closed",
    "W05": "Witness outage blocks acceptance without rewriting historical PROVEN or advancing ledger",
    "W06": "Restart same witness key/DB and reconcile exact pending event once without duplicate packet refs",
    "W07": "Invariant damage DISPROVEN; actual baseline restoration RECOVERED; all receipts verified",
    "W08": "Silent TLS peer does not block authenticated checkpoint; unknown CA is refused",
    "W09": "Fresh offline process replays public-only wrappers after witness and target stop",
    "W10": "Published 0.3.1 portable-v2 golden proof remains readable with the installed candidate",
}


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding="utf-8")


def read(path):
    return json.loads(Path(path).read_bytes())


def private_write(path, raw):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def helpers():
    path = Path(__file__).with_name("verify_multihost.py")
    spec = importlib.util.spec_from_file_location("ace_multihost_transport", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(arguments):
    return helpers().remote_command(arguments)


def remote(alias, arguments, **kwargs):
    return helpers().remote(alias, command(arguments), **kwargs)


def checked_local(arguments, log=None, timeout=180, cwd=None):
    if cwd is None:
        return helpers().run([str(value) for value in arguments], log=log, timeout=timeout)
    done = subprocess.run(
        [str(value) for value in arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=cwd,
        timeout=timeout,
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
    )
    if log:
        Path(log).write_text(done.stdout + done.stderr, encoding="utf-8")
    require(done.returncode == 0, "OFFLINE_VERIFIER_PROCESS_FAILED")
    return done.stdout


def require(condition, code):
    if not condition:
        raise ValueError(code)


def remote_guard(root):
    root = Path(root).resolve()
    require(root.parent == Path.home().resolve() and root.name.startswith("ace-g3-witness-"), "REMOTE_SCOPE")
    require(root.is_dir(), "REMOTE_ROOT_MISSING")
    return root


def start_ticks(pid):
    return (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]


def remote_setup(args):
    """Runs from the exact remote installed package; only public enrollment is returned."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from closure_engine.crypto import TrustStore
    from closure_engine.time_witness import initialize

    root = remote_guard(args.root)
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
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACE physical temporal witness")]))
        .sign(key, hashes.SHA256())
    )
    private_write(tls / "server.csr", csr.public_bytes(serialization.Encoding.PEM))
    trust = TrustStore.from_dict(read(root / "authority-trust.json"))
    enrolled = initialize(root / "witness", "physical-witness-" + root.name, trust, args.authority_pin)
    # Pinned by the SSH operator before any request uses this identity.
    save(root / "enrollment.json", enrolled)
    return {
        "machine": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "system_utc": datetime.now(UTC).isoformat(),
        "witness_hash": enrolled["expected_witness_hash"],
        "authority_hash": trust.hash,
        "leaf_private_key_transferred": False,
        "witness_private_key_transferred": False,
    }


def remote_start(args):
    root = remote_guard(args.root)
    registry = root / "processes.json"
    records = read(registry) if registry.exists() else []
    for record in records:
        require(record["stopped"], "OWNED_WITNESS_ALREADY_RUNNING")
    enrolled = read(root / "enrollment.json")
    arguments = [
        str(root / "venv/bin/python"),
        "-I",
        "-m",
        "closure_engine.time_witness",
        "serve",
        "--root",
        str(root / "witness"),
        "--expected-witness-hash",
        enrolled["expected_witness_hash"],
        "--expected-authority-hash",
        args.authority_pin,
        "--host",
        args.bind,
        "--port",
        str(args.port),
        "--allowed-host",
        args.bind + ":" + str(args.port),
        "--tls-cert",
        str(root / "tls/server.crt"),
        "--tls-key",
        str(root / "tls/server.key"),
    ]
    log_path = root / ("witness-" + str(len(records)) + ".log")
    with log_path.open("wb") as log:
        process = subprocess.Popen(arguments, cwd=root, stdout=log, stderr=log, start_new_session=True)
    require(process.pid != FORBIDDEN_PID, "RESERVED_PID")
    # Register even startup failures so finally always has exact scoped PID ownership.
    record = {
        "pid": process.pid,
        "start_ticks": start_ticks(process.pid),
        "command": arguments,
        "stopped": False,
        "log": str(log_path),
    }
    records.append(record)
    save(registry, records)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        require(process.poll() is None, "OWNED_WITNESS_START_FAILED")
        if '"LISTENING"' in log_path.read_text(errors="replace"):
            return {
                "pid": process.pid,
                "port": args.port,
                "witness_hash": enrolled["expected_witness_hash"],
                "restart_index": len(records) - 1,
                "system_utc": datetime.now(UTC).isoformat(),
            }
        time.sleep(0.05)
    raise ValueError("OWNED_WITNESS_START_TIMEOUT")


def remote_stop(args):
    root = remote_guard(args.root)
    registry = root / "processes.json"
    if not registry.exists():
        return {"stopped": [], "never_started": True}
    records, results = read(registry), []
    for record in records:
        pid = record["pid"]
        require(pid != FORBIDDEN_PID, "RESERVED_PID")
        proc = Path("/proc") / str(pid)
        if record["stopped"] or not proc.exists():
            record["stopped"] = True
            continue
        raw_command = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        require(
            start_ticks(pid) == record["start_ticks"]
            and str(root / "venv/bin/python") in raw_command
            and str(root / "witness") in raw_command,
            "OWNED_PID_GUARD_REFUSED",
        )
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while proc.exists() and time.monotonic() < deadline:
            if (proc / "stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
                break
            time.sleep(0.05)
        if proc.exists() and (proc / "stat").read_text().rsplit(")", 1)[1].split()[0] != "Z":
            require(start_ticks(pid) == record["start_ticks"], "OWNED_PID_GUARD_REFUSED")
            os.kill(pid, signal.SIGKILL)
        record["stopped"] = True
        results.append({"pid": pid, "status": "STOPPED"})
    save(registry, records)
    return {"stopped": results}


def target_artifact(answer, other="stable"):
    return json.dumps(
        {"routes": {"/answer": {"answer": answer}, "/config": {"mode": "safe"}, "/other": {"value": other}}},
        sort_keys=True,
    ).encode()


def prepare(args):
    from closure_engine.runtime import (
        ROLES,
        Deployment,
        ReferenceTarget,
        enroll,
        enroll_target,
        init_identity,
    )

    root = Path(args.root)
    deployment = Deployment(root / "ace")
    checks = [
        {
            "id": "primary",
            "kind": "primary",
            "phase": "instant",
            "mandatory": True,
            "probe": {"type": "http-json", "path": "/answer", "pointer": "/answer"},
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
            "probe": {"type": "staged-artifact"},
        },
        {
            "id": "baseline",
            "kind": "baseline",
            "phase": "instant",
            "mandatory": True,
            "probe": {"type": "baseline-custody"},
        },
    ]
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "physical-g2-" + role)
    pin = enroll(deployment, [item["id"] for item in checks])["trust_hash"]
    target = enroll_target(deployment, "physical/time", "http://127.0.0.1:" + str(args.port), checks)
    ReferenceTarget.initialize(root / "target", target_artifact(1), target["deploy_token_sha256"])
    return {
        "machine": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "authority_hash": pin,
        "target_port": args.port,
        "system_utc": datetime.now(UTC).isoformat(),
    }


def runtime_for(config):
    from closure_engine.runtime import Deployment, Runtime

    return Runtime(Deployment(Path(config["root"]) / "ace"), config["authority_hash"])


def execute(runtime, tx, raw=None):
    if raw is not None:
        runtime.propose(
            "physical/time",
            tx,
            raw,
            intent="Authorized answer correction preserving configuration",
            expect={"primary": json.loads(raw)["routes"]["/answer"]["answer"]},
            duration_ms=3000,
            min_samples=3,
            max_clock_skew_ms=1000,
            settle_ms=2500,
            proposed_by="physical-agent",
        )
    runtime.approve(tx, approved_by="physical-owner", require_independent=True)
    runtime.freeze(tx)
    runtime.baseline(tx)
    runtime.bind(tx)
    deployed = runtime.deploy(tx)
    require(deployed["receipt"] == "EXECUTED", "REAL_DEPLOYMENT_NOT_EXECUTED")
    runtime.observe(tx, phase="all")
    result = runtime.close(tx)
    if result["state"] == "OBSERVING":
        result = runtime.close(tx)
    return result


def public_record(runtime, tx, config):
    from closure_engine.protocol import digest
    from closure_engine.runtime.portable import encode_bundle
    from closure_engine.time_assurance import verify_time_assurance

    proof = runtime.time_assurance(tx)
    expected = {
        "expected_authority_hash": config["authority_hash"],
        "expected_witness_hash": config["witness_hash"],
        "expected_transaction": tx,
        "expected_contract_hash": digest(proof["portable_bundle"]["contract"]),
        "expected_artifact_hash": runtime.status(tx)["artifact_hash"],
    }
    result = verify_time_assurance(proof, **expected)
    folder = Path(config["root"]) / "public"
    folder.mkdir(exist_ok=True)
    path = folder / (tx + ".json")
    path.write_bytes(encode_bundle(proof))
    save(folder / (tx + "-expected.json"), expected)
    require(result["time_assurance"]["status"] == "HISTORICAL_WITNESSED", "TEMPORAL_REPLAY_NOT_WITNESSED")
    return {
        "proof_file": str(path),
        "proof_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "expected": expected,
        "result": result,
        "sidecars": len(proof["sidecars"]),
    }


def positive(config):
    from closure_engine.protocol import ClosureError
    from closure_engine.time_assurance import verify_time_assurance

    runtime = runtime_for(config)
    result = execute(runtime, "physical-proven", target_artifact(2))
    require(result["verdict"] == "PROVEN", "VALID_CHANGE_NOT_PROVEN")
    require(runtime.accept("physical-proven")["state"] == "ACCEPTED", "ACCEPTANCE_FAILED")
    record = public_record(runtime, "physical-proven", config)
    proof, expected = read(record["proof_file"]), dict(record["expected"])
    failures = {}
    for attack in ("pin-b", "signature"):
        altered, pins = copy.deepcopy(proof), dict(expected)
        if attack == "pin-b":
            pins["expected_witness_hash"] = "sha256:" + "0" * 64
        else:
            altered["sidecars"][0]["receipt"]["signature"] = "00" * 64
        try:
            verify_time_assurance(altered, **pins)
        except ClosureError as exc:
            failures[attack] = exc.code
        else:
            raise ValueError("ADVERSARY_ACCEPTED: " + attack)
    # A second real proven transaction will exercise acceptance under actual witness outage.
    pending = execute(runtime, "physical-outage", target_artifact(3))
    require(pending["verdict"] == "PROVEN", "OUTAGE_CONTROL_NOT_PROVEN")
    from closure_engine.protocol import canonical

    packet = runtime.closure("physical-outage")
    save(
        Path(config["root"]) / "outage-baseline.json",
        {
            "packet_sha256": hashlib.sha256(canonical(packet)).hexdigest(),
            "head": runtime.status("physical-outage")["ledger_head"],
            "packets": runtime.status("physical-outage")["packets"],
        },
    )
    return {"accepted": record, "negative_controls": failures, "outage_transaction": pending}


def outage(config):
    from closure_engine.protocol import ClosureError, canonical

    runtime = runtime_for(config)
    baseline = read(Path(config["root"]) / "outage-baseline.json")
    started = time.monotonic()
    try:
        runtime.accept("physical-outage")
    except ClosureError as exc:
        code = exc.code
    else:
        raise ValueError("WITNESS_OUTAGE_ACCEPTED")
    require("UNAVAILABLE" in code, "OUTAGE_FAILURE_NOT_TYPED_UNAVAILABLE")
    require(runtime.status("physical-outage")["state"] == "PROVEN", "OUTAGE_REWROTE_TECHNICAL_VERDICT")
    require(runtime.status("physical-outage")["ledger_head"] == baseline["head"], "OUTAGE_ADVANCED_LEDGER")
    require(
        hashlib.sha256(canonical(runtime.closure("physical-outage"))).hexdigest()
        == baseline["packet_sha256"],
        "OUTAGE_CHANGED_PACKET",
    )
    pending = read(runtime.custody.root / "witness/pending.json")
    require(pending["status"] == "PREPARED", "OUTAGE_PENDING_NOT_DURABLE")
    save(
        Path(config["root"]) / "outage-pending-public.json",
        {
            "event_hash": pending["event_hash"],
            "nonce": pending["nonce"],
            "contract_hash": pending["subject"]["payload"]["body"]["contract_hash"],
        },
    )
    return {
        "error": code,
        "elapsed_seconds": time.monotonic() - started,
        "technical_state": "PROVEN",
        "unchanged_head": baseline["head"],
        "pending_event_hash": pending["event_hash"],
    }


def reconcile(config):
    from closure_engine.protocol import canonical, digest
    from closure_engine.runtime.witness_gate import reconcile_witness_operation

    runtime = runtime_for(config)
    before = read(runtime.custody.root / "witness/pending.json")
    original = read(Path(config["root"]) / "outage-baseline.json")
    reconcile_witness_operation(runtime.custody)
    require(runtime.status("physical-outage")["state"] == "ACCEPTED", "RESTART_RECONCILIATION_NOT_ACCEPTED")
    after = read(runtime.custody.root / "witness/pending.json")
    require(
        after["event_hash"] == before["event_hash"]
        and after["nonce"] == before["nonce"]
        and after["status"] == "COMPLETE",
        "RECONCILIATION_CHANGED_PENDING_SUBJECT",
    )
    head = runtime.status("physical-outage")["ledger_head"]
    reconcile_witness_operation(runtime.custody)
    require(runtime.status("physical-outage")["ledger_head"] == head, "RETRY_DUPLICATED_EVENT")
    require(
        runtime.status("physical-outage")["packets"] == original["packets"], "RETRY_DUPLICATED_PACKET_REFS"
    )
    require(
        hashlib.sha256(canonical(runtime.closure("physical-outage"))).hexdigest()
        == original["packet_sha256"],
        "RECONCILIATION_CHANGED_TECHNICAL_PACKET",
    )
    record = public_record(runtime, "physical-outage", config)
    return {
        "exact_event_hash": digest(after["event"]),
        "nonce_preserved": True,
        "idempotent_head": head,
        "accepted": record,
    }


def recovery(config):
    from closure_engine.protocol import digest
    from closure_engine.runtime.target import TargetClient

    runtime = runtime_for(config)
    baseline = TargetClient(runtime.deployment.target("physical/time")).artifact()
    result = execute(runtime, "physical-recovery", target_artifact(4, other="damaged"))
    require(result["verdict"] == "DISPROVEN", "INVARIANT_DAMAGE_NOT_DISPROVEN")
    proposal = runtime.begin_recovery("physical-recovery", proposed_by="physical-recovery-agent")
    child = proposal["transaction_id"]
    require(execute(runtime, child)["verdict"] == "PROVEN", "BASELINE_RESTORATION_NOT_PROVEN")
    require(runtime.complete_recovery("physical-recovery")["state"] == "RECOVERED", "RECOVERY_NOT_ADMITTED")
    restored = TargetClient(runtime.deployment.target("physical/time")).artifact()
    require(restored == baseline, "RESTORED_BASELINE_BYTES_DIFFER")
    return {
        "baseline_hash": digest(baseline),
        "restored_hash": digest(restored),
        "child": child,
        "recovery": public_record(runtime, "physical-recovery", config),
    }


def tls_controls(config):
    parsed = config["bind"], config["port"]
    silent = socket.create_connection(parsed, timeout=3)
    try:
        context = ssl.create_default_context(cafile=config["ca_file"])
        token = Path(config["token_file"]).read_text().strip()
        opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=context))
        started = time.monotonic()
        message = request.Request(
            config["endpoint"] + "/checkpoint", headers={"Authorization": "Bearer " + token}
        )
        with opener.open(message, timeout=4) as response:
            checkpoint = json.loads(response.read())
        duration = time.monotonic() - started
        require(duration < 4, "SILENT_TLS_PEER_BLOCKED_ACTIVE_CLIENT")
        time.sleep(max(0, 5.5 - (time.monotonic() - started)))
        silent.settimeout(2)
        ended = False
        try:
            ended = silent.recv(1) == b""
        except ConnectionResetError:
            ended = True
        require(ended, "SILENT_TLS_PEER_NOT_TIMED_OUT")
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        untrusted.check_hostname, untrusted.verify_mode = True, ssl.CERT_REQUIRED
        try:
            with socket.create_connection(parsed, timeout=4) as channel:
                with untrusted.wrap_socket(channel, server_hostname=config["bind"]):
                    pass
        except ssl.SSLCertVerificationError:
            unknown = "CERTIFICATE_VERIFY_FAILED"
        else:
            raise ValueError("UNTRUSTED_CA_ACCEPTED")
        return {
            "authenticated_checkpoint": checkpoint,
            "active_elapsed_seconds": duration,
            "silent_peer_timeout": True,
            "unknown_ca": unknown,
        }
    finally:
        silent.close()


def proof_negatives(config):
    from closure_engine.protocol import ClosureError
    from closure_engine.runtime.files import replace_json
    from closure_engine.time_assurance import verify_time_assurance

    root = Path(config["root"])
    folder = root / "public"
    proof = read(folder / "physical-recovery.json")
    pins = read(folder / "physical-recovery-expected.json")
    rejected = []
    for index in range(len(proof["sidecars"])):
        altered = copy.deepcopy(proof)
        missing = altered["sidecars"].pop(index)
        try:
            verify_time_assurance(altered, **pins)
        except ClosureError as exc:
            require(exc.code == "TIME_ASSURANCE_REQUIRED_RECEIPT_MISSING", "MISSING_RECEIPT_UNEXPECTED_ERROR")
            rejected.append(
                {"missing_state": missing["event"]["payload"]["body"]["state"], "error": exc.code}
            )
        else:
            raise ValueError("MISSING_RECOVERY_RECEIPT_ACCEPTED")
    # Actual required operator policy, not a caller-supplied query pin. Preserve bytes and
    # restore only this fresh controller-owned policy after the deliberate wrong-pin probe.
    profile = root / "ace/operator/witness-gate.json"
    original = profile.read_bytes()
    wrong = read(profile)
    wrong["expected_witness_hash"] = "sha256:" + "0" * 64
    head = runtime_for(config).status("physical-recovery")["ledger_head"]
    try:
        replace_json(profile, wrong)
        try:
            runtime_for(config)
        except ClosureError as exc:
            wrong_policy = exc.code
            require(wrong_policy == "WITNESS_PIN_MISMATCH", "OPERATOR_WRONG_PIN_UNEXPECTED_ERROR")
        else:
            raise ValueError("OPERATOR_WRONG_PIN_STARTED")
    finally:
        temporary = profile.with_name(profile.name + ".restore-" + secrets.token_hex(8))
        private_write(temporary, original)
        os.replace(temporary, profile)
    require(profile.read_bytes() == original, "OPERATOR_PROFILE_BYTES_NOT_RESTORED")
    require(
        runtime_for(config).status("physical-recovery")["ledger_head"] == head, "WRONG_PIN_ADVANCED_LEDGER"
    )
    return {
        "missing_recovery_receipts": rejected,
        "operator_wrong_pin": wrong_policy,
        "restored_exact_profile": True,
        "unchanged_head": head,
    }


def offline(config):
    folder = Path(config["root"]) / "public"
    outcomes = {}
    for tx in ("physical-proven", "physical-outage", "physical-recovery"):
        arguments = [
            sys.executable,
            "-I",
            "-m",
            "closure_engine.time_assurance",
            "--proof",
            str(folder / (tx + ".json")),
        ]
        for name, value in read(folder / (tx + "-expected.json")).items():
            arguments.extend(["--" + name.replace("_", "-"), value])
        result = json.loads(checked_local(arguments, folder / (tx + "-offline.log"), cwd=folder))
        require(result["time_assurance"]["status"] == "HISTORICAL_WITNESSED", "OFFLINE_REPLAY_FAILED")
        outcomes[tx] = result
    golden = Path(config["golden"])
    manifest = read(golden / "manifest.json")
    require(
        hashlib.sha256((golden / "proof.json").read_bytes()).hexdigest() == manifest["proof_sha256"],
        "GOLDEN_BYTES_CHANGED",
    )
    arguments = [
        sys.executable,
        "-I",
        "-m",
        "closure_engine.runtime.portable",
        "--bundle",
        str(golden / "proof.json"),
        "--expected-trust-hash",
        (golden / "trust-pin.txt").read_text().strip(),
        "--expected-transaction",
        manifest["transaction_id"],
        "--expected-artifact-hash",
        manifest["expected_artifact_hash"],
        "--require-proven",
    ]
    outcomes["published-031-golden"] = json.loads(
        checked_local(arguments, folder / "golden-offline.log", cwd=folder)
    )
    require(outcomes["published-031-golden"]["closure"]["verdict"] == "PROVEN", "GOLDEN_VERDICT_CHANGED")
    return outcomes


def orchestrate(args):
    transport = helpers()
    wheel, lock, out = Path(args.ace_wheel).resolve(), Path(args.lock).resolve(), Path(args.out_dir).resolve()
    require(transport.sha(wheel) == args.ace_sha256, "OPERATOR_WHEEL_PIN_MISMATCH")
    bind = ipaddress.ip_address(args.bind)
    require(
        bind.is_private and not bind.is_loopback and not bind.is_multicast and not bind.is_link_local,
        "PRIVATE_BIND_REQUIRED",
    )
    require(1024 <= args.port <= 65535 and args.port not in FORBIDDEN_PORTS, "RESERVED_OR_INVALID_PORT")
    out.mkdir(parents=True, exist_ok=False)
    (out / "receiver").mkdir()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    root = args.remote_parent.rstrip("/") + "/ace-g3-witness-" + stamp
    local_root = out / "windows"
    local_root.mkdir()
    local_py = out / "venv/Scripts/python.exe"
    remote_py = root + "/venv/bin/python"
    script = str(Path(__file__).resolve())
    remote_script = root + "/verify_multihost_witness.py"
    result = {
        "status": "EXECUTING",
        "phase": "preflight",
        "registered_expectations": EXPECTATIONS,
        "candidate_wheel_sha256": args.ace_sha256,
        "requirements_sha256": transport.sha(lock),
        "controller_sha256": transport.sha(script),
        "transport_helpers_sha256": transport.sha(Path(script).with_name("verify_multihost.py")),
        "remote_root": root,
        "excluded_pid": FORBIDDEN_PID,
        "excluded_ports": sorted(FORBIDDEN_PORTS),
    }
    save(out / "registration.json", result)
    created, target = False, None
    try:
        checked_local([sys.executable, "-m", "venv", str(out / "venv")], out / "local-venv.log")
        checked_local(
            [local_py, "-m", "pip", "install", "--require-hashes", "-r", lock],
            out / "local-dependencies.log",
            timeout=360,
        )
        checked_local([local_py, "-m", "pip", "install", "--no-deps", wheel], out / "local-install.log")
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            target_port = channel.getsockname()[1]
        require(target_port not in FORBIDDEN_PORTS, "RESERVED_TARGET_PORT")
        prepared = json.loads(
            checked_local(
                [local_py, "-I", script, "--phase", "prepare", "--root", local_root, "--port", target_port],
                out / "local-prepare.log",
            )
        )
        result["local_machine"] = prepared
        pin = prepared["authority_hash"]
        remote_preflight = (
            "import json,pathlib,platform,socket,os; r=pathlib.Path(" + repr(root) + "); "
            "assert r.parent.resolve()==pathlib.Path.home().resolve(); assert not r.exists(); "
            "s=socket.socket(); s.bind((" + repr(args.bind) + "," + str(args.port) + ")); s.close(); "
            "os.umask(0o077); r.mkdir(mode=0o700); "
            "print(json.dumps({'machine':platform.node(),'platform':platform.platform()}))"
        )
        result["remote_preflight"] = json.loads(
            remote(args.ssh_alias, ["python3", "-c", remote_preflight], log=out / "remote-preflight.log")
        )
        created = True
        require(result["remote_preflight"]["machine"] != prepared["machine"], "HOST_IDENTITIES_NOT_DISTINCT")
        for source, name in [
            (wheel, wheel.name),
            (lock, "requirements.lock"),
            (Path(script), "verify_multihost_witness.py"),
            (Path(script).with_name("verify_multihost.py"), "verify_multihost.py"),
            (local_root / "ace/operator/trust.json", "authority-trust.json"),
        ]:
            transport.transfer(args.ssh_alias, source, root + "/" + name)
        remote(args.ssh_alias, ["python3", "-m", "venv", root + "/venv"], log=out / "remote-venv.log")
        remote(
            args.ssh_alias,
            [remote_py, "-m", "pip", "install", "--require-hashes", "-r", root + "/requirements.lock"],
            log=out / "remote-dependencies.log",
            timeout=360,
        )
        remote(
            args.ssh_alias,
            [remote_py, "-m", "pip", "install", "--no-deps", root + "/" + wheel.name],
            log=out / "remote-install.log",
        )
        result["local_integrity"] = json.loads(
            checked_local(
                [
                    local_py,
                    "-I",
                    script,
                    "--phase",
                    "integrity",
                    "--ace-wheel",
                    wheel,
                    "--ace-sha256",
                    args.ace_sha256,
                ],
                out / "local-integrity.log",
            )
        )
        result["remote_integrity"] = json.loads(
            remote(
                args.ssh_alias,
                [
                    remote_py,
                    "-I",
                    remote_script,
                    "--phase",
                    "integrity",
                    "--ace-wheel",
                    root + "/" + wheel.name,
                    "--ace-sha256",
                    args.ace_sha256,
                ],
                log=out / "remote-integrity.log",
            )
        )
        result["witness_enrollment"] = json.loads(
            remote(
                args.ssh_alias,
                [
                    remote_py,
                    "-I",
                    remote_script,
                    "--phase",
                    "remote-setup",
                    "--root",
                    root,
                    "--authority-pin",
                    pin,
                ],
                log=out / "remote-enrollment.log",
            )
        )
        for name, local in [
            ("enrollment.json", out / "enrollment.json"),
            ("tls/server.csr", out / "receiver/server.csr"),
            ("witness/client.token", local_root / "witness-client.token"),
        ]:
            transport.transfer(args.ssh_alias, local, root + "/" + name, download=True)
        os.chmod(local_root / "witness-client.token", 0o600)
        enrolled = read(out / "enrollment.json")
        require(
            enrolled["expected_witness_hash"] == result["witness_enrollment"]["witness_hash"],
            "SSH_PIN_CHANGED",
        )
        result["tls_enrollment"] = json.loads(
            checked_local(
                [local_py, "-I", script, "--phase", "certificate", "--out-dir", out, "--bind", args.bind],
                out / "certificate.log",
            )
        )
        transport.transfer(args.ssh_alias, out / "tls/server.crt", root + "/tls/server.crt")
        profile = {
            "version": "v1",
            "endpoint": "https://" + args.bind + ":" + str(args.port),
            "manifest": enrolled["manifest"],
            "expected_witness_hash": enrolled["expected_witness_hash"],
            "expected_authority_hash": pin,
            "token_file": str(local_root / "witness-client.token"),
            "ca_file": str(out / "tls/private-ca.crt"),
            "timeout_ms": 5000,
        }
        save(local_root / "ace/operator/witness-gate.json", profile)
        config = {
            "root": str(local_root),
            "authority_hash": pin,
            "witness_hash": enrolled["expected_witness_hash"],
            "bind": args.bind,
            "port": args.port,
            "endpoint": profile["endpoint"],
            "ca_file": profile["ca_file"],
            "token_file": profile["token_file"],
            "golden": str(Path(script).parents[1] / "tests/fixtures/portable_v2_golden"),
        }
        save(out / "config.json", config)
        base_remote = [
            remote_py,
            "-I",
            remote_script,
            "--root",
            root,
            "--authority-pin",
            pin,
            "--bind",
            args.bind,
            "--port",
            args.port,
        ]
        result["witness_start"] = json.loads(
            remote(args.ssh_alias, [*base_remote, "--phase", "remote-start"], log=out / "remote-start.log")
        )
        log = (out / "target.log").open("wb")
        target = subprocess.Popen(
            [
                str(local_py),
                "-I",
                script,
                "--phase",
                "target",
                "--root",
                str(local_root),
                "--port",
                str(target_port),
            ],
            stdout=log,
            stderr=log,
        )
        log.close()
        time.sleep(0.5)
        require(target.poll() is None, "LOCAL_TARGET_NOT_RUNNING")

        def phase(name):
            result["phase"] = name
            save(out / "progress.json", result)
            measured = json.loads(
                checked_local(
                    [local_py, "-I", script, "--phase", name, "--config", out / "config.json"],
                    out / (name + ".log"),
                    timeout=240,
                )
            )
            result[name] = measured
            return measured

        phase("tls-controls")
        phase("positive")
        result["outage_stop"] = json.loads(
            remote(
                args.ssh_alias, [*base_remote, "--phase", "remote-stop"], log=out / "remote-outage-stop.log"
            )
        )
        phase("outage")
        result["witness_restart"] = json.loads(
            remote(args.ssh_alias, [*base_remote, "--phase", "remote-start"], log=out / "remote-restart.log")
        )
        require(
            result["witness_restart"]["witness_hash"] == result["witness_start"]["witness_hash"],
            "RESTART_IDENTITY_CHANGED",
        )
        phase("reconcile")
        phase("recovery")
        phase("proof-negatives")
        result["final_witness_stop"] = json.loads(
            remote(
                args.ssh_alias, [*base_remote, "--phase", "remote-stop"], log=out / "remote-final-stop.log"
            )
        )
        target.terminate()
        target.wait(timeout=8)
        result["target_stopped_before_offline"] = target.poll() is not None
        phase("offline")
        result["status"], result["phase"] = "Worked", "complete"
    except Exception as exc:
        result["status"] = "Failed"
        result["error"] = {"type": type(exc).__name__, "reason": str(exc)}
        raise
    finally:
        if target is not None and target.poll() is None:
            target.terminate()
            target.wait(timeout=8)
        if created:
            try:
                result["cleanup"] = json.loads(
                    remote(
                        args.ssh_alias,
                        [remote_py, "-I", remote_script, "--phase", "remote-stop", "--root", root],
                        log=out / "remote-cleanup.log",
                    )
                )
            except Exception as exc:
                result["cleanup"] = {"error": type(exc).__name__}
                result["status"] = "Failed"
        result["scope"] = (
            "Physical Windows runtime + Linux Spark2 separately keyed witness and OS clock; "
            "same operator administration; witness system UTC is trusted, not absolute UTC."
        )
        save(out / "handback.json", result)
    return {"status": result["status"], "receipt": str(out / "handback.json"), "remote_root": root}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        default="orchestrate",
        choices=[
            "orchestrate",
            "integrity",
            "prepare",
            "target",
            "certificate",
            "remote-setup",
            "remote-start",
            "remote-stop",
            "positive",
            "outage",
            "reconcile",
            "recovery",
            "tls-controls",
            "offline",
            "proof-negatives",
        ],
    )
    parser.add_argument("--root")
    parser.add_argument("--config")
    parser.add_argument("--authority-pin")
    parser.add_argument("--ace-wheel")
    parser.add_argument("--ace-sha256")
    parser.add_argument("--lock")
    parser.add_argument("--out-dir")
    parser.add_argument("--ssh-alias", default="spark2")
    parser.add_argument("--remote-parent", default="/home/rblake2320")
    parser.add_argument("--bind", default="192.168.12.220")
    parser.add_argument("--port", type=int, default=18762)
    args = parser.parse_args()
    if args.phase == "orchestrate":
        if not all((args.ace_wheel, args.ace_sha256, args.lock, args.out_dir)):
            parser.error("exact wheel/hash/lock and NEW evidence directory required")
        result = orchestrate(args)
    elif args.phase == "integrity":
        result = helpers().installed_integrity(args.ace_wheel, args.ace_sha256, "closure_engine")
    elif args.phase == "certificate":
        result = helpers().sign_remote_csr(Path(args.out_dir), args.bind)
    elif args.phase == "target":
        from closure_engine.runtime import ReferenceTargetServer

        server = ReferenceTargetServer(("127.0.0.1", args.port), Path(args.root) / "target")
        print(json.dumps({"status": "LISTENING", "port": args.port}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return
    elif args.phase in {"prepare", "remote-setup", "remote-start", "remote-stop"}:
        result = {
            "prepare": prepare,
            "remote-setup": remote_setup,
            "remote-start": remote_start,
            "remote-stop": remote_stop,
        }[args.phase](args)
    else:
        result = {
            "positive": positive,
            "outage": outage,
            "reconcile": reconcile,
            "recovery": recovery,
            "tls-controls": tls_controls,
            "offline": offline,
            "proof-negatives": proof_negatives,
        }[args.phase](read(args.config))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
