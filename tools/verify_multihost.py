"""Reproducible two-machine ACE TLS producer -> Windows public-only AWL admission gate.

Runs only in a new remote home/ace-g3-* directory and new local evidence directory.
Requires operator-approved SSH alias/private address and exact independently supplied wheel
digests. No global trust/ACL/firewall changes; all owned service PIDs stopped on completion.
"""

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import platform
import shlex
import socket
import ssl
import subprocess
import sys
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib import error, request

SSH_OPTIONS = ["-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
EXPECTATIONS = {
    "G3-01": "Linux producer and Windows receiver are distinct actual machines",
    "G3-02": "Both hosts install the exact independently pinned candidate ACE wheel; receiver also pins AWL",
    "G3-03": "Remote leaf private key and all ACE signing/deployment keys never copied to Windows",
    "G3-04": "Fresh actual static publication PROVEN and separately ACCEPTED",
    "G3-05": "Wrong deployed static content DISPROVEN then RECOVERED with exact failed-run baseline ZIP",
    "G3-06": "Windows public-only portable proof and live network ledger replay agree with signed outcomes",
    "G3-07": "AWL accepts matching PROVEN and records DISPROVEN as CORRECTION_REQUIRED",
    "G3-08": "Changed packet stays pending; wrong independent trust pin is refused",
    "G3-09": "Unknown TLS CA and wrong hostname fail with trusted active control",
    "G3-10": "Viewer cannot mutate gateway; 403 with unchanged checkpoint",
    "G3-11": "Gateway outage blocks a new dependent claim despite prior verified historical acceptance",
    "G3-12": "Only recorded own PIDs stopped; all machine receipts and private runtime state preserved",
}


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding="utf-8")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def installed_integrity(wheel, expected_hash, package):
    """Measure the imported installed package bytes against the exact pinned wheel."""
    import importlib

    if sha(wheel) != expected_hash:
        raise ValueError("INTEGRITY_WHEEL_HASH_MISMATCH")
    imported = importlib.import_module(package)
    location = Path(imported.__file__).parent
    verified = {}
    with zipfile.ZipFile(wheel) as artifact:
        for member in artifact.namelist():
            if not member.startswith(package + "/") or member.endswith("/"):
                continue
            relative = member.partition("/")[2]
            actual = (location / relative).read_bytes()
            if actual != artifact.read(member):
                raise ValueError("INSTALLED_PACKAGE_BYTES_MISMATCH: " + member)
            verified[member] = hashlib.sha256(actual).hexdigest()
    if not verified:
        raise ValueError("INSTALLED_PACKAGE_FILES_MISSING")
    return {"wheel_sha256": expected_hash, "installed_origin": str(location), "verified_files": verified}


def run(command, *, log=None, data=None, env=None, timeout=300):
    environment = dict(os.environ if env is None else env, PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        command,
        input=data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        timeout=timeout,
    )
    if result.stdout is None or result.stderr is None:
        raise RuntimeError("PROCESS_OUTPUT_CAPTURE_FAILED")
    if log:
        Path(log).write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        # Command arguments never carry bearer tokens/private key contents. Avoid reflecting
        # arbitrary server response bodies or environment in a public error report.
        raise RuntimeError(f"PROCESS_FAILED exit={result.returncode} executable={Path(command[0]).name}")
    return result.stdout


def remote(alias, command, *, log=None, data=None, timeout=300):
    return run(["ssh", *SSH_OPTIONS, alias, command], log=log, data=data, timeout=timeout)


def remote_command(arguments):
    return " ".join(shlex.quote(str(argument)) for argument in arguments)


def transfer(alias, local, remote_path, *, download=False):
    destination = alias + ":" + remote_path
    args = [destination, str(local)] if download else [str(local), destination]
    run(["scp", *SSH_OPTIONS, *args], timeout=120)


def sign_remote_csr(out, bind):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    tls = out / "tls"
    tls.mkdir()
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key_path = tls / "private-ca.key"
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(
            ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Independent ACE G3 private CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    csr = x509.load_pem_x509_csr((out / "receiver/server.csr").read_bytes())
    if not csr.is_signature_valid:
        raise ValueError("REMOTE_CSR_SIGNATURE_INVALID")
    leaf = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(bind))]), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (tls / "private-ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tls / "server.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (out / "receiver/private-ca.crt").write_bytes((tls / "private-ca.crt").read_bytes())
    return {
        "ca_sha256": sha(tls / "private-ca.crt"),
        "leaf_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
        "san_ip": bind,
        "ca_private_key_transferred": False,
    }


def wrong_hostname_certificate(out):
    """Real trusted issuer signs the remote CSR with a deliberately mismatching SAN."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca = x509.load_pem_x509_certificate((out / "tls/private-ca.crt").read_bytes())
    key = serialization.load_pem_private_key((out / "tls/private-ca.key").read_bytes(), password=None)
    csr = x509.load_pem_x509_csr((out / "receiver/server.csr").read_bytes())
    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("wrong-host.invalid")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    path = out / "tls/wrong-host.crt"
    path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    return path


def api_call(url, token, method, path, body=None):
    opener = request.build_opener(request.ProxyHandler({}))
    headers = {"Authorization": "Bearer " + token}
    raw = None if body is None else json.dumps(body).encode()
    if raw is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(url + path, data=raw, headers=headers, method=method)
    try:
        with opener.open(req, timeout=20) as response:
            status, data = response.status, response.read(64 * 1024 * 1024 + 1)
    except error.HTTPError as exc:
        status, data = exc.code, exc.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("RECEIVER_RESPONSE_LIMIT")
    return status, json.loads(data)


def tls_controls(config):
    # Endpoint selection is explicit, not a hostname derived from a potentially changed proof.
    address, port = config["bind"], config["port"]
    accepted = ssl.create_default_context(cafile=config["ca_file"])
    outcomes = {}
    for label, context, name in (
        ("trusted", accepted, address),
        ("unknown_ca", ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), address),
        ("wrong_hostname", accepted, "wrong-host.invalid"),
    ):
        try:
            with socket.create_connection((address, port), timeout=10) as transport:
                with context.wrap_socket(transport, server_hostname=name) as secured:
                    fingerprint = hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()
                    if label != "trusted":
                        raise AssertionError("TLS_NEGATIVE_ACCEPTED")
                    assert fingerprint == config["leaf_sha256"]
                    outcomes[label] = {
                        "accepted": True,
                        "leaf_sha256": fingerprint,
                        "protocol": secured.version(),
                    }
        except ssl.SSLCertVerificationError as exc:
            if label == "trusted":
                raise
            outcomes[label] = {"accepted": False, "code": exc.verify_code, "reason": exc.verify_message}
    return outcomes


def receiver(config_path, outage=False, network_negative=False, label=None):
    from importlib.metadata import version

    from work_ledger.core import WorkError, WorkLedger
    from work_ledger.network_adapter import NetworkAceAdapter

    from closure_engine.crypto import TrustStore
    from closure_engine.protocol import digest
    from closure_engine.runtime.portable import verify_bundle

    config_path = Path(config_path)
    config = json.loads(config_path.read_bytes())
    root = config_path.parent
    token = (root / "viewer.token").read_text().strip()
    trust = TrustStore.from_dict(json.loads((root / "trust.json").read_bytes()))
    pin = (root / "trust.pin").read_text().strip()
    checkpoint = json.loads((root / "checkpoint.json").read_bytes())
    adapter = NetworkAceAdapter(trust, pin, config["url"], token, prior_checkpoint=checkpoint, timeout=60)
    ledger_path = root / "work.sqlite"

    def now():
        return int(time.time() * 1000)

    if network_negative:
        from work_ledger.verification import VerificationUnavailable

        envelope = json.loads((root / "g3-publication-envelope.json").read_bytes())
        expected = json.loads((root / "manifest.json").read_bytes())["transactions"]["g3-publication"][
            "expected"
        ]
        if label == "trusted-active":
            verdict = adapter.verify(envelope, expected)
            assert verdict["verdict"] == "PROVEN"
            return {"client": "NetworkAceAdapter", "verdict": "PROVEN", "active": True}
        ledger = WorkLedger(root / (label + "-negative.sqlite"), closure_adapter=adapter)
        ledger.create_project("tls-negative", "Actual network client TLS refusal", now())
        ledger.create_task(
            "bound-task",
            "tls-negative",
            "Must never accept untrusted TLS",
            now(),
            acceptance="ACE",
            expected_closure=expected,
        )
        lease = ledger.claim(
            "bound-task", "windows-worker", 60000, now(), ledger.context("bound-task")["revision"]
        )
        ledger.report(
            "bound-task",
            "windows-worker",
            lease["lease"]["token"],
            lease["revision"],
            expected["artifact_hash"],
            now(),
        )
        try:
            adapter.verify(envelope, expected)
        except VerificationUnavailable as exc:
            refusal = str(exc)
        else:
            raise AssertionError("NETWORK_TLS_NEGATIVE_ACCEPTED")
        try:
            ledger.admit_closure("bound-task", envelope, now())
        except WorkError as exc:
            assert str(exc) == "ASSURANCE_VERIFICATION_UNAVAILABLE"
        else:
            raise AssertionError("AWL_TLS_NEGATIVE_ACCEPTED")
        assert ledger.task("bound-task")["state"] == "VERIFICATION_PENDING"
        return {
            "client": "NetworkAceAdapter",
            "label": label,
            "refusal": refusal,
            "awl_refusal": "ASSURANCE_VERIFICATION_UNAVAILABLE",
            "task_state": "VERIFICATION_PENDING",
        }

    if outage:
        ledger = WorkLedger(ledger_path, closure_adapter=adapter, create=False)
        refused = None
        try:
            ledger.claim(
                "outage-dependent",
                "windows-worker",
                60000,
                now(),
                ledger.context("outage-dependent")["revision"],
            )
        except WorkError as exc:
            refused = str(exc)
        assert refused == "DEPENDENCY_VERIFICATION_UNAVAILABLE", refused
        assert ledger.task("outage-dependent")["state"] == "TODO"
        receipt = {
            "claim_denied": refused,
            "task_state": "TODO",
            "prior_acceptance_retained": ledger.task("verified-publication")["state"] == "COMPLETE",
            "database_hash": sha(ledger_path),
        }
        save(root / "outage-receipt.json", receipt)
        return receipt
    assert os.name == "nt", "Receiver must be the actual Windows machine"
    transport = tls_controls(config)
    status, who = api_call(config["url"], token, "GET", "/api/v1/whoami")
    assert status == 200 and who["roles"] == ["viewer"] and who["approval_mode"] == "role-scoped"
    manifest = json.loads((root / "manifest.json").read_bytes())
    envelopes, outcomes = {}, {}
    for tx, expected in manifest["transactions"].items():
        status, bundle = api_call(config["url"], token, "GET", "/api/v1/transactions/" + tx + "/bundle")
        assert status == 200
        save(root / (tx.replace("/", "-") + "-bundle.json"), bundle)
        public = verify_bundle(
            bundle,
            pin,
            prior_checkpoint=checkpoint,
            expected_transaction=tx,
            expected_contract_hash=expected["expected"]["contract_hash"],
            expected_artifact_hash=expected["expected"]["artifact_hash"],
        )
        status, envelope = api_call(config["url"], token, "GET", "/api/v1/transactions/" + tx + "/closure")
        assert status == 200
        envelopes[tx] = envelope
        save(root / (tx.replace("/", "-") + "-envelope.json"), envelope)
        network = adapter.verify(envelope, expected["expected"])
        assert network["verdict"] == public["closure"]["verdict"] == expected["verdict"]
        outcomes[tx] = {
            "portable_verdict": public["closure"]["verdict"],
            "network_verdict": network["verdict"],
            "packet_hash": digest(envelope["packet"]),
            "evidence_objects": public["evidence_objects"],
            "checkpoint_verified": public["external_prior_checkpoint_checked"],
        }
    wrong_pin = "sha256:" + ("0" if pin[7] != "0" else "1") + pin[8:]
    try:
        NetworkAceAdapter(trust, wrong_pin, config["url"], token)
    except ValueError as exc:
        assert str(exc) == "TRUST_ANCHOR_MISMATCH"
    else:
        raise AssertionError("WRONG_PIN_ACCEPTED")
    ledger = WorkLedger(ledger_path, closure_adapter=adapter)
    ledger.create_project(
        "linux-customer-release", "Cross-machine customer publication with independent receiving proof", now()
    )

    def pending(task_id, tx):
        expected = manifest["transactions"][tx]["expected"]
        ledger.create_task(
            task_id,
            "linux-customer-release",
            "Cross-machine evidence-bound outcome",
            now(),
            acceptance="ACE",
            expected_closure=expected,
        )
        lease = ledger.claim(
            task_id,
            "windows-worker",
            60000,
            now(),
            ledger.context(task_id)["revision"],
            capability_required=True,
        )
        ledger.report(
            task_id,
            "windows-worker",
            lease["lease"]["token"],
            lease["revision"],
            expected["artifact_hash"],
            now(),
            lease_id=lease["lease_id"],
        )

    pending("verified-publication", "g3-publication")
    changed = copy.deepcopy(envelopes["g3-publication"])
    signature = changed["packet"]["signature"]
    changed["packet"]["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
    try:
        ledger.admit_closure("verified-publication", changed, now())
    except WorkError as exc:
        assert str(exc).startswith("CLOSURE_REJECTED")
    else:
        raise AssertionError("TAMPERED_PACKET_ACCEPTED")
    assert ledger.task("verified-publication")["state"] == "VERIFICATION_PENDING"
    admitted = ledger.admit_closure("verified-publication", envelopes["g3-publication"], now())
    assert admitted["state"] == "COMPLETE" and admitted["assurance"] == "INDEPENDENTLY_VERIFIED"
    pending("wrong-publication", "g3-wrong-content")
    rejected = ledger.admit_closure("wrong-publication", envelopes["g3-wrong-content"], now())
    assert rejected["state"] == "CORRECTION_REQUIRED"
    pending("verified-recovery", "g3-wrong-content/recovery")
    recovered = ledger.admit_closure("verified-recovery", envelopes["g3-wrong-content/recovery"], now())
    assert recovered["state"] == "COMPLETE" and recovered["assurance"] == "INDEPENDENTLY_VERIFIED"
    ledger.create_task(
        "active-dependent",
        "linux-customer-release",
        "Eligible dependency active control",
        now(),
        dependencies=["verified-publication"],
    )
    active = ledger.claim(
        "active-dependent", "windows-worker", 60000, now(), ledger.context("active-dependent")["revision"]
    )
    assert active["lease"]["agent_id"] == "windows-worker"
    ledger.create_task(
        "outage-dependent",
        "linux-customer-release",
        "Must remain queued on live verifier outage",
        now(),
        dependencies=["verified-publication"],
    )
    status, denied = api_call(config["url"], token, "POST", "/api/v1/reconcile", {})
    assert status == 403 and denied["error"] == "ROLE_REQUIRED"
    viewer_write_status = status
    # Public checkpoint must remain unchanged after the refused write attempt.
    status, page = api_call(config["url"], token, "GET", "/api/v1/audit-export?from=1&limit=1000")
    assert status == 200 and page["checkpoint"]["payload"]["body"] == checkpoint["payload"]["body"]
    receipt = {
        "machine": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "ace_version": version("agentic-closure-engine"),
        "awl_version": version("agent-work-ledger"),
        "tls": transport,
        "whoami": who,
        "outcomes": outcomes,
        "awl_positive": {"state": admitted["state"], "assurance": admitted["assurance"]},
        "awl_failure_state": rejected["state"],
        "awl_recovery": {"state": recovered["state"], "assurance": recovered["assurance"]},
        "tampered_signature_refused_pending": True,
        "wrong_trust_pin_refused": True,
        "viewer_write_status": viewer_write_status,
        "active_dependency_claimed": True,
        "copied_ACE_signing_keys": [],
        "checkpoint_hash": digest(checkpoint),
        "database_hash": sha(ledger_path),
    }
    assert not list(root.glob("*.key")), "No private keys are allowed in the receiving proof root"
    save(root / "receiver-receipt.json", receipt)
    return receipt


def orchestrate(args):
    if os.name != "nt":
        raise ValueError("ORCHESTRATOR_REQUIRES_WINDOWS_RECEIVER")
    address = ipaddress.ip_address(args.bind)
    if not address.is_private or address.is_loopback or address.is_multicast or address.is_link_local:
        raise ValueError("PRIVATE_REMOTE_INTERFACE_REQUIRED")
    if (
        any(not 1024 <= port <= 65535 for port in (args.port, args.target_port))
        or args.port == args.target_port
    ):
        raise ValueError("PRIVATE_PORTS_INVALID")
    out = Path(args.out_dir).absolute()
    if out.exists():
        raise ValueError("NEW_EVIDENCE_DIRECTORY_REQUIRED")
    for wheel, expected in ((args.ace_wheel, args.ace_sha256), (args.awl_wheel, args.awl_sha256)):
        if sha(wheel) != expected:
            raise ValueError("LOCAL_WHEEL_HASH_MISMATCH")
    out.mkdir(parents=True)
    (out / "receiver").mkdir()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    root = args.remote_parent.rstrip("/") + "/ace-g3-" + stamp + "-" + os.urandom(3).hex()
    executable = root + "/venv/bin/python"
    producer = root + "/multihost_producer.py"
    registration = {
        "registered_at": datetime.now(UTC).isoformat(),
        "expected": EXPECTATIONS,
        "remote_root": root,
        "ssh_alias": args.ssh_alias,
        "private_bind": args.bind,
        "ports": {"tls": args.port, "target_loopback": args.target_port},
        "ace_sha256": args.ace_sha256,
        "awl_sha256": args.awl_sha256,
        "dependency_locks": {
            name: sha(path) for name, path in (("ace", args.ace_lock), ("awl", args.awl_lock)) if path
        },
        "restrictions": (
            "new own roots only; no global CA/ACL/firewall/shared service changes; "
            "viewer secret only crosses to Windows"
        ),
    }
    save(out / "registered-expectations.json", registration)
    result = {"status": "EXECUTING", "registration": registration, "phase": "registered", "cleanup": None}
    created = False
    try:
        result["phase"] = "remote-preflight"
        preflight = f"""import os,pathlib,socket,platform,json
root=pathlib.Path({root!r}); parent=pathlib.Path({args.remote_parent!r})
assert parent.resolve()==pathlib.Path.home().resolve(), 'REMOTE_PARENT_MUST_BE_HOME'
assert not root.exists(), 'REMOTE_ROOT_ALREADY_EXISTS'
assert platform.system()=='Linux'
for host,port in [({args.bind!r},{args.port}),('127.0.0.1',{args.target_port})]:
 with socket.socket() as sock: sock.bind((host,port))
os.umask(0o077);root.mkdir(mode=0o700)
print(json.dumps({{'machine':platform.node(),'platform':platform.platform(),'python':platform.python_version(),'root':str(root)}}))
"""
        result["remote_preflight"] = json.loads(
            remote(args.ssh_alias, "python3 -", data=preflight, log=out / "remote-preflight.log")
        )
        created = True
        transfer(args.ssh_alias, args.ace_wheel, root + "/" + Path(args.ace_wheel).name)
        transfer(args.ssh_alias, Path(__file__).with_name("multihost_producer.py"), producer)
        result["phase"] = "remote-install"
        remote(
            args.ssh_alias,
            remote_command(["python3", "-m", "venv", root + "/venv"]),
            log=out / "remote-venv.log",
        )
        if args.ace_lock:
            transfer(args.ssh_alias, args.ace_lock, root + "/requirements-runtime.lock")
            remote(
                args.ssh_alias,
                remote_command(
                    [
                        executable,
                        "-m",
                        "pip",
                        "install",
                        "--require-hashes",
                        "-r",
                        root + "/requirements-runtime.lock",
                    ]
                ),
                log=out / "remote-locked-dependencies.log",
            )
        remote(
            args.ssh_alias,
            remote_command(
                [
                    executable,
                    "-m",
                    "pip",
                    "install",
                    *(["--no-deps"] if args.ace_lock else []),
                    root + "/" + Path(args.ace_wheel).name,
                ]
            ),
            log=out / "remote-install.log",
        )
        transfer(args.ssh_alias, Path(__file__).absolute(), root + "/verify_multihost.py")
        result["linux_installed_integrity"] = json.loads(
            remote(
                args.ssh_alias,
                remote_command(
                    [
                        executable,
                        "-I",
                        root + "/verify_multihost.py",
                        "--phase",
                        "integrity",
                        "--ace-wheel",
                        root + "/" + Path(args.ace_wheel).name,
                        "--ace-sha256",
                        args.ace_sha256,
                    ]
                ),
            )
        )
        result["phase"] = "remote-csr"
        result["certificate_preparation"] = json.loads(
            remote(args.ssh_alias, remote_command([executable, "-I", producer, "csr", "--root", root]))
        )
        transfer(args.ssh_alias, out / "receiver/server.csr", root + "/tls/server.csr", download=True)
        result["tls_enrollment"] = sign_remote_csr(out, args.bind)
        transfer(args.ssh_alias, out / "tls/server.crt", root + "/tls/server.crt")
        transfer(args.ssh_alias, out / "tls/private-ca.crt", root + "/tls/private-ca.crt")
        result["phase"] = "real-linux-producer"
        result["producer"] = json.loads(
            remote(
                args.ssh_alias,
                remote_command(
                    [
                        executable,
                        "-I",
                        producer,
                        "produce",
                        "--root",
                        root,
                        "--bind",
                        args.bind,
                        "--target-port",
                        args.target_port,
                        "--port",
                        args.port,
                        "--wheel-sha256",
                        args.ace_sha256,
                    ]
                ),
                log=out / "producer.log",
            )
        )
        for name in ("trust.json", "trust.pin", "checkpoint.json", "manifest.json", "producer-receipt.json"):
            transfer(args.ssh_alias, out / "receiver" / name, root + "/public/" + name, download=True)
        transfer(args.ssh_alias, out / "receiver/viewer.token", root + "/viewer.token", download=True)
        result["gateway"] = json.loads(
            remote(
                args.ssh_alias,
                remote_command(
                    [
                        executable,
                        "-I",
                        producer,
                        "gateway",
                        "--root",
                        root,
                        "--bind",
                        args.bind,
                        "--port",
                        args.port,
                    ]
                ),
            )
        )
        result["phase"] = "windows-install"
        run([sys.executable, "-m", "venv", str(out / "receiver-venv")], log=out / "windows-venv.log")
        python = out / "receiver-venv/Scripts/python.exe"
        for name, lock in (("ace", args.ace_lock), ("awl", args.awl_lock)):
            if lock:
                run(
                    [
                        str(python),
                        "-m",
                        "pip",
                        "install",
                        "--require-hashes",
                        "-r",
                        str(Path(lock).absolute()),
                    ],
                    log=out / ("windows-" + name + "-locked-dependencies.log"),
                )
        run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                *(["--no-deps"] if args.ace_lock and args.awl_lock else []),
                str(Path(args.ace_wheel).absolute()),
                str(Path(args.awl_wheel).absolute()),
            ],
            log=out / "windows-install.log",
        )
        result["windows_installed_integrity"] = json.loads(
            run(
                [
                    str(python),
                    "-I",
                    str(Path(__file__).absolute()),
                    "--phase",
                    "integrity",
                    "--ace-wheel",
                    str(Path(args.ace_wheel).absolute()),
                    "--ace-sha256",
                    args.ace_sha256,
                    "--awl-wheel",
                    str(Path(args.awl_wheel).absolute()),
                    "--awl-sha256",
                    args.awl_sha256,
                ],
            )
        )
        config = {
            "bind": args.bind,
            "port": args.port,
            "url": f"https://{args.bind}:{args.port}",
            "ca_file": str(out / "receiver/private-ca.crt"),
            "leaf_sha256": result["tls_enrollment"]["leaf_sha256"],
        }
        save(out / "receiver/config.json", config)
        environment = dict(os.environ, SSL_CERT_FILE=config["ca_file"])
        result["phase"] = "windows-receiver"
        result["receiver"] = json.loads(
            run(
                [
                    str(python),
                    "-I",
                    str(Path(__file__).absolute()),
                    "--phase",
                    "receiver",
                    "--config",
                    str(out / "receiver/config.json"),
                ],
                env=environment,
                log=out / "receiver.log",
            )
        )
        assert result["producer"]["machine"] != result["receiver"]["machine"]
        result["phase"] = "actual-network-TLS-negative-controls"
        negative_command = [
            str(python),
            "-I",
            str(Path(__file__).absolute()),
            "--phase",
            "network-negative",
            "--config",
            str(out / "receiver/config.json"),
            "--negative-label",
        ]
        result["network_trusted_active"] = json.loads(
            run(negative_command + ["trusted-active"], env=environment)
        )
        untrusted_environment = dict(environment)
        untrusted_environment.pop("SSL_CERT_FILE", None)
        untrusted_environment.pop("SSL_CERT_DIR", None)
        result["network_unknown_ca"] = json.loads(
            run(negative_command + ["unknown-ca"], env=untrusted_environment)
        )
        result["phase"] = "controlled-gateway-outage"
        result["gateway_stop"] = json.loads(
            remote(
                args.ssh_alias,
                remote_command([executable, "-I", producer, "stop", "--root", root, "--kind", "gateway"]),
            )
        )
        transfer(args.ssh_alias, wrong_hostname_certificate(out), root + "/tls/wrong-host.crt")
        result["wrong_hostname_gateway"] = json.loads(
            remote(
                args.ssh_alias,
                remote_command(
                    [
                        executable,
                        "-I",
                        producer,
                        "gateway",
                        "--root",
                        root,
                        "--bind",
                        args.bind,
                        "--port",
                        args.port,
                        "--kind",
                        "gateway-hostname-negative",
                        "--cert-name",
                        "wrong-host.crt",
                    ]
                ),
            )
        )
        result["network_wrong_hostname"] = json.loads(
            run(negative_command + ["wrong-hostname"], env=environment)
        )
        result["wrong_hostname_gateway_stop"] = json.loads(
            remote(
                args.ssh_alias,
                remote_command(
                    [
                        executable,
                        "-I",
                        producer,
                        "stop",
                        "--root",
                        root,
                        "--kind",
                        "gateway-hostname-negative",
                    ]
                ),
            )
        )
        result["outage"] = json.loads(
            run(
                [
                    str(python),
                    "-I",
                    str(Path(__file__).absolute()),
                    "--phase",
                    "outage",
                    "--config",
                    str(out / "receiver/config.json"),
                ],
                env=environment,
                log=out / "outage.log",
            )
        )
        result["status"] = "Worked"
        result["phase"] = "complete"
    except Exception as exc:
        result["status"] = "Failed"
        result["error"] = {"type": type(exc).__name__, "reason": str(exc)}
        raise
    finally:
        if created:
            try:
                result["cleanup"] = json.loads(
                    remote(
                        args.ssh_alias, remote_command([executable, "-I", producer, "stop", "--root", root])
                    )
                )
            except Exception as exc:
                result["cleanup"] = {"error": type(exc).__name__}
                result["status"] = "Failed"
        result["scope"] = (
            "actual Linux aarch64 producer -> Windows receiver over private LAN TLS; "
            "producer all-key administrative identity, no OS role-isolation claim"
        )
        save(out / "handback.json", result)
    return {"status": result["status"], "receipt": str(out / "handback.json"), "remote_root": root}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=("orchestrate", "receiver", "outage", "integrity", "network-negative", "wrong-certificate"),
        default="orchestrate",
    )
    parser.add_argument("--config")
    parser.add_argument("--negative-label", choices=("trusted-active", "unknown-ca", "wrong-hostname"))
    parser.add_argument("--ace-lock")
    parser.add_argument("--awl-lock")
    parser.add_argument("--ace-wheel")
    parser.add_argument("--ace-sha256")
    parser.add_argument("--awl-wheel")
    parser.add_argument("--awl-sha256")
    parser.add_argument("--ssh-alias", default="spark2")
    parser.add_argument("--remote-parent", default="/home/rblake2320")
    parser.add_argument("--bind", default="192.168.12.220")
    parser.add_argument("--port", type=int, default=18742)
    parser.add_argument("--target-port", type=int, default=18743)
    parser.add_argument("--out-dir")
    args = parser.parse_args()
    if args.phase == "wrong-certificate":
        result = {"public_wrong_hostname_certificate": str(wrong_hostname_certificate(Path(args.out_dir)))}
    elif args.phase == "network-negative":
        result = receiver(args.config, network_negative=True, label=args.negative_label)
    elif args.phase == "integrity":
        result = {"ace": installed_integrity(args.ace_wheel, args.ace_sha256, "closure_engine")}
        if args.awl_wheel:
            result["awl"] = installed_integrity(args.awl_wheel, args.awl_sha256, "work_ledger")
    elif args.phase != "orchestrate":
        result = receiver(args.config, outage=args.phase == "outage")
    else:
        if not all((args.ace_wheel, args.ace_sha256, args.awl_wheel, args.awl_sha256, args.out_dir)):
            parser.error("orchestration requires both exact wheel paths/digests and a NEW output directory")
        result = orchestrate(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
