"""Real TLS signing service, deployed targets and abrupt custody-process fault boundaries."""

import http.client
import ipaddress
import json
import os
import queue
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from test_runtime_e2e import WINDOW, artifact, expect_of, run_to_verdict, world  # noqa: F401

from closure_engine.crypto import sign
from closure_engine.ledger import Ledger
from closure_engine.protocol import ClosureError, canonical, digest, milliseconds, timestamp
from closure_engine.runtime import Deployment, Runtime
from closure_engine.runtime.files import create_exclusive, create_json, read_json, replace_json
from closure_engine.runtime.witness_gate import (
    WitnessGate,
    _config,
    _receipt,
    reconcile_witness_operation,
    witness_record,
)
from closure_engine.store import EvidenceStore
from closure_engine.time_witness import Witness, initialize, make_server


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    root = tmp_path_factory.mktemp("witness-tls")
    ca_key, server_key = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Witness test CA")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
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
            True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), False)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    create_exclusive(root / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    create_exclusive(root / "server.pem", cert.public_bytes(serialization.Encoding.PEM))
    create_exclusive(
        root / "server.key",
        server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        private=True,
    )
    return root


@pytest.fixture
def gated(world, tmp_path, tls):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    root = tmp_path / "witness-service"
    enrolled = initialize(root, "independent-time-signer", runtime.trust, pin)
    witness = Witness(root, enrolled["expected_witness_hash"], pin)
    server = make_server(witness, port=0, certificate=tls / "server.pem", tls_key=tls / "server.key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = {
        "version": "v1",
        "endpoint": "https://127.0.0.1:" + str(server.server_address[1]),
        "manifest": witness.manifest,
        "expected_witness_hash": digest(witness.manifest),
        "expected_authority_hash": pin,
        "token_file": str((root / "client.token").resolve()),
        "ca_file": str((tls / "ca.pem").resolve()),
        "timeout_ms": 1000,
    }
    create_json(deployment.role_root("operator") / "witness-gate.json", config)
    runtime = Runtime(deployment, pin)  # startup enrolls sticky required marker
    yield runtime, witness, server, deployment, pin
    server.shutdown()
    server.server_close()


def propose(runtime, tx="witnessed"):
    runtime.propose(
        "shop/api",
        tx,
        artifact(2),
        intent="Real outcome correction",
        expect=expect_of(artifact(2)),
        duration_ms=WINDOW["duration_ms"],
        min_samples=WINDOW["min_samples"],
        max_clock_skew_ms=WINDOW["max_clock_skew_ms"],
        settle_ms=WINDOW["settle_ms"],
    )
    runtime.approve(tx)


def event(runtime, tx, state, *, at=None, packet=None):
    head, seq = runtime.custody.position()
    role = "owner" if state == "ACCEPTED" else "authority"
    body = {
        "event_id": "gate-event-" + secrets.token_hex(12),
        "transaction_id": tx,
        "contract_hash": digest(runtime._tx(tx)["contract"]),
        "sequence": seq + 1,
        "previous_hash": head,
        "state": state,
        "refs": [],
        "packet": packet,
        "binding": None,
        "receipt": None,
        "recovery_contract": None,
        "recovery_approval": None,
        "risk": None,
    }
    return sign(runtime._identity(role), "ledger-event", body, at or runtime.clock.now()), head


def test_unconfigured_runtime_stays_normal_without_witness_files(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    assert run_to_verdict(runtime, "normal-no-witness", artifact(2))[1]["verdict"] == "PROVEN"
    assert runtime.accept("normal-no-witness")["state"] == "ACCEPTED"
    assert not (runtime.custody.root / "witness").exists()


def test_real_proven_and_owner_acceptance_require_event_and_closure_receipts(gated):
    runtime, witness, _, _, _ = gated
    assert run_to_verdict(runtime, "witnessed", artifact(2))[1]["verdict"] == "PROVEN"
    assert runtime.accept("witnessed")["state"] == "ACCEPTED"
    events = runtime.custody.audit_export()["events"]
    kinds = []
    for envelope in events:
        role = runtime.trust.record(envelope["payload"]["key_id"])["role"]
        if role == "authority" or envelope["payload"]["body"]["state"] == "ACCEPTED":
            record = witness_record(runtime.custody, digest(envelope))
            kinds.append(record["receipt"]["body"]["subject_purpose"])
            assert record["event"] == envelope
    assert "ledger-event" in kinds and "closure-packet" in kinds
    assert witness.checkpoint()["sequence"] == len(kinds)


@pytest.mark.parametrize("change", ["delete", "malformed", "pin-change", "token-reference-missing"])
def test_required_config_never_silently_switches_off(gated, change):
    runtime, _, _, deployment, pin = gated
    propose(runtime)
    profile = deployment.role_root("operator") / "witness-gate.json"
    if change == "delete":
        profile.unlink()
    elif change == "malformed":
        profile.write_bytes(b'{"wrong":true}')
    else:
        config = read_json(profile, "missing")
        if change == "pin-change":
            config["timeout_ms"] += 1
        else:
            Path(config["token_file"]).unlink()
        replace_json(profile, config)
    before = runtime.custody.position()
    with pytest.raises(ClosureError):
        runtime.freeze("witnessed")
    assert runtime.custody.position() == before
    assert runtime.custody.state("witnessed") == "APPROVED"
    with pytest.raises(ClosureError):
        Runtime(deployment, pin)


def test_witness_outage_refuses_terminal_and_acceptance_without_changing_historical_verdict(gated):
    runtime, _, server, _, _ = gated
    assert run_to_verdict(runtime, "witnessed", artifact(2))[1]["verdict"] == "PROVEN"
    packet = canonical(runtime.closure("witnessed"))
    before = runtime.custody.position()
    server.shutdown()
    server.server_close()
    with pytest.raises(ClosureError, match="WITNESS_GATE_RECEIPT_UNAVAILABLE"):
        runtime.accept("witnessed")
    assert runtime.custody.position() == before
    assert runtime.custody.state("witnessed") == "PROVEN"
    assert canonical(runtime.closure("witnessed")) == packet


def test_future_recovery_failed_is_refused_before_native_admission(gated, tmp_path):
    runtime, witness, _, _, _ = gated
    assert run_to_verdict(runtime, "damaged", artifact(3, other="changed"))[1]["verdict"] == "DISPROVEN"
    assert runtime.custody.state("damaged") == "RECOVERY_REQUIRED"
    parent = runtime.custody.technical_packet("damaged")["payload"]["body"]
    future = (
        milliseconds(parent["evaluated_at"])
        + runtime._tx("damaged")["contract"]["recovery"]["deadline_ms"]
        + 1
    )
    submitted, head = event(runtime, "damaged", "RECOVERY_FAILED", at=timestamp(future))
    # Red baseline: the native signer-time kernel admits this authentic future-dated event.
    clone = tmp_path / "native-copy"
    clone.mkdir()
    shutil.copytree(runtime.custody.store.root, clone / "evidence")
    with sqlite3.connect(runtime.custody.root / "ledger.sqlite") as source:
        with sqlite3.connect(clone / "ledger.sqlite") as destination:
            source.backup(destination)
    ledger = Ledger(
        clone / "ledger.sqlite",
        runtime.trust,
        EvidenceStore(clone / "evidence"),
        checkpoint=runtime.custody.checkpoint(),
    )
    ledger.append(submitted, head)
    assert ledger.state("damaged") == "RECOVERY_FAILED"
    before = witness.checkpoint()
    with pytest.raises(ClosureError, match="WITNESS_EVENT_FUTURE"):
        runtime.custody.append(submitted, head)
    assert runtime.custody.ledger.head == head
    assert runtime.custody.state("damaged") == "RECOVERY_REQUIRED"
    assert witness.checkpoint() == before


def _crash(runtime, deployment, pin, stage, tmp_path, tx="witnessed"):
    """Fault injector pauses AFTER the real commit/append; the parent then kills the process."""
    driver = tmp_path / ("kill-" + stage + ".py")
    driver.write_text(
        """import json,sys
from closure_engine.runtime import Deployment,Runtime
from closure_engine.runtime.witness_gate import SignedConsumerJournal,WitnessGate
runtime=Runtime(Deployment(sys.argv[1]),sys.argv[2])
def pause():
    print("BOUNDARY",flush=True)
    sys.stdin.readline()
if sys.argv[3]=="consumed":
    original=SignedConsumerJournal.consume_bound
    def wrapped(self,*args,**kw):
        result=original(self,*args,**kw)
        pause()
        return result
    SignedConsumerJournal.consume_bound=wrapped
    runtime.freeze(sys.argv[4])
else:
    original=WitnessGate.complete
    def wrapped(self,pending):
        if pending and pending["event"]["payload"]["body"]["state"]=="PROVEN": pause()
        return original(self,pending)
    WitnessGate.complete=wrapped
    result=runtime.close(sys.argv[4])
    if result["state"]=="OBSERVING": runtime.close(sys.argv[4])
""",
        encoding="utf-8",
    )
    command = [sys.executable]
    env = dict(os.environ)
    if os.environ.get("TIME_WITNESS_INSTALLED") == "1":
        command.append("-I")
    else:
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    command.extend([str(driver), str(deployment.root), pin, stage, tx])
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True
    )
    output = queue.Queue()
    threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True).start()
    try:
        received = output.get(timeout=30)
        assert received.strip() == "BOUNDARY", received + process.stderr.read()
    finally:
        process.kill()
        process.wait(timeout=5)
    return read_json(runtime.custody.root / "witness" / "pending.json", "pending missing")


def test_real_kill_after_signed_consumption_before_append_resumes_exact_event(gated, tmp_path):
    runtime, witness, _, deployment, pin = gated
    propose(runtime)
    before = runtime.custody.position()
    pending = _crash(runtime, deployment, pin, "consumed", tmp_path)
    assert pending["status"] == "RECEIVED"  # committed signed journal, pending not yet updated
    again = Runtime(Deployment(deployment.root), pin)
    assert again.custody.position() == before
    receipt_position = witness.checkpoint()
    result = reconcile_witness_operation(again.custody)
    assert result["event_hash"] == pending["event_hash"]
    assert again.custody.state("witnessed") == "FROZEN"
    assert witness.checkpoint() == receipt_position  # no new receipt / blind consume
    assert reconcile_witness_operation(again.custody) == result


def test_real_kill_after_append_before_completion_preserves_unique_packet_refs(gated, tmp_path):
    runtime, witness, _, deployment, pin = gated
    propose(runtime)
    runtime.freeze("witnessed")
    runtime.baseline("witnessed")
    runtime.bind("witnessed")
    runtime.deploy("witnessed")
    runtime.observe("witnessed", phase="all")
    pending = _crash(runtime, deployment, pin, "appended", tmp_path)
    again = Runtime(Deployment(deployment.root), pin)
    assert again.custody.state("witnessed") == "PROVEN"
    before = again.custody.position()
    refs = list(again._tx("witnessed")["packets"])
    packet = canonical(again.custody.technical_packet("witnessed"))
    receipt_position = witness.checkpoint()
    result = reconcile_witness_operation(again.custody)
    assert result["event_hash"] == pending["event_hash"]
    assert again.custody.position() == before
    assert again._tx("witnessed")["packets"] == refs
    assert len(refs) == len(set(refs))
    assert canonical(again.custody.technical_packet("witnessed")) == packet
    assert witness.checkpoint() == receipt_position


def test_different_event_pending_conflict_is_denied_before_witness_call(gated, tmp_path):
    runtime, witness, _, deployment, pin = gated
    propose(runtime)
    _crash(runtime, deployment, pin, "consumed", tmp_path)
    again = Runtime(Deployment(deployment.root), pin)
    before = witness.checkpoint()
    other, head = event(again, "witnessed", "FROZEN")
    with pytest.raises(ClosureError, match="WITNESS_GATE_PENDING_CONFLICT"):
        again.custody.append(other, head)
    assert witness.checkpoint() == before
    assert again.custody.state("witnessed") == "APPROVED"


def test_fake_journal_row_cannot_authorize_pending_event(gated, tmp_path):
    runtime, _, _, deployment, pin = gated
    propose(runtime)
    _crash(runtime, deployment, pin, "consumed", tmp_path)
    path = runtime.custody.root / "witness" / "consumed.sqlite"
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT proof FROM consumed").fetchone()[0]
        proof = json.loads(row)
        proof["payload"]["body"]["event_hash"] = digest(b"forged-event")
        db.execute("UPDATE consumed SET proof=?", (canonical(proof),))
    again = Runtime(Deployment(deployment.root), pin)
    with pytest.raises(ClosureError, match="WITNESS_GATE_SIGNATURE_INVALID"):
        reconcile_witness_operation(again.custody)
    assert again.custody.state("witnessed") == "APPROVED"


def test_first_malformed_configuration_is_sticky_even_after_deletion(world):  # noqa: F811
    deployment, pin, _ = world
    profile = deployment.role_root("operator") / "witness-gate.json"
    profile.write_bytes(b'{"invalid":true}')
    with pytest.raises(ClosureError, match="WITNESS_GATE_CONFIG_INVALID"):
        Runtime(deployment, pin)
    profile.unlink()
    with pytest.raises(ClosureError, match="WITNESS_GATE_CONFIG_MISSING"):
        Runtime(deployment, pin)


def test_validly_signed_receipt_for_wrong_subject_is_refused(gated):
    runtime, witness, _, _, _ = gated
    propose(runtime)
    submitted, head = event(runtime, "witnessed", "FROZEN")
    config = _config(runtime.custody)
    gate = WitnessGate(runtime.custody, config)
    pending = gate._bind(submitted, head)
    different, _ = event(runtime, "witnessed", "FROZEN")
    pending["receipt"] = _receipt(config, different, pending["nonce"])
    pending["status"] = "RECEIVED"
    replace_json(gate.pending_path, pending)
    before = witness.checkpoint()
    with pytest.raises(ClosureError, match="WITNESS_PACKET_MISMATCH"):
        runtime.custody.append(submitted, head)
    assert witness.checkpoint() == before
    assert runtime.custody.state("witnessed") == "APPROVED"


def test_tampered_pending_subject_refused_before_witness_call(gated):
    runtime, witness, _, _, _ = gated
    propose(runtime)
    submitted, head = event(runtime, "witnessed", "FROZEN")
    gate = WitnessGate(runtime.custody, _config(runtime.custody))
    pending = gate._bind(submitted, head)
    pending["subject"], _ = event(runtime, "witnessed", "FROZEN")
    replace_json(gate.pending_path, pending)
    before = witness.checkpoint()
    with pytest.raises(ClosureError, match="WITNESS_GATE_PENDING_INVALID"):
        runtime.custody.append(submitted, head)
    assert witness.checkpoint() == before


def test_actor_acceptance_event_is_denied_before_witness_call(gated):
    runtime, witness, _, _, _ = gated
    assert run_to_verdict(runtime, "witnessed", artifact(2))[1]["verdict"] == "PROVEN"
    submitted, head = event(runtime, "witnessed", "ACCEPTED")
    submitted = sign(
        runtime._identity("actor"), "ledger-event", submitted["payload"]["body"], runtime.clock.now()
    )
    before = witness.checkpoint()
    with pytest.raises(ClosureError, match="STATE_AUTHORITY_DENIED"):
        runtime.custody.append(submitted, head)
    assert witness.checkpoint() == before
    assert runtime.custody.state("witnessed") == "PROVEN"


def test_silent_tcp_before_clienthello_does_not_block_authenticated_witness(gated):
    runtime, witness, server, _, _ = gated
    propose(runtime)
    silent = socket.create_connection(server.server_address, timeout=2)
    try:
        time.sleep(0.1)  # ensure the accept loop has seen the real silent peer
        started = time.monotonic()
        assert runtime.freeze("witnessed")["state"] == "FROZEN"
        assert time.monotonic() - started < 3
        assert witness.checkpoint()["sequence"] == 1
        silent.settimeout(7)
        try:
            closed = silent.recv(1) == b""
        except ConnectionResetError:
            closed = True
        assert closed  # worker's actual TLS read deadline fired
        propose(runtime, "after-peer-timeout")
        assert runtime.freeze("after-peer-timeout")["state"] == "FROZEN"
        assert witness.checkpoint()["sequence"] == 2
    finally:
        silent.close()


def test_export_sidecar_cannot_substitute_unsigned_policy_digest(gated):
    runtime, _, _, _, _ = gated
    assert run_to_verdict(runtime, "witnessed", artifact(2))[1]["verdict"] == "PROVEN"
    envelope = next(
        e for e in runtime.custody.audit_export()["events"] if e["payload"]["body"]["state"] == "PROVEN"
    )
    event_hash = digest(envelope)
    record = witness_record(runtime.custody, event_hash)
    record["config_hash"] = digest(b"unapproved-policy")
    replace_json(runtime.custody.root / "witness" / "receipts" / (event_hash[7:] + ".json"), record)
    with pytest.raises(ClosureError, match="WITNESS_GATE_RECORD_INVALID"):
        witness_record(runtime.custody, event_hash)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_recovery_failure_deadline_must_be_observed_by_witness_clock(gated, phase):
    runtime, witness, _, _, _ = gated
    tx, raw = "short-recovery", artifact(3, other="changed")
    runtime.propose(
        "shop/api",
        tx,
        raw,
        intent="Deadline boundary test",
        expect=expect_of(raw),
        duration_ms=WINDOW["duration_ms"],
        min_samples=WINDOW["min_samples"],
        max_clock_skew_ms=WINDOW["max_clock_skew_ms"],
        settle_ms=WINDOW["settle_ms"],
        recovery_deadline_ms=6000,
    )
    runtime.approve(tx)
    runtime.freeze(tx)
    runtime.baseline(tx)
    runtime.bind(tx)
    runtime.deploy(tx)
    runtime.observe(tx, phase="all")
    result = runtime.close(tx)
    if result["state"] == "OBSERVING":
        result = runtime.close(tx)
    assert result["verdict"] == "DISPROVEN"
    parent = runtime.custody.technical_packet(tx)["payload"]["body"]
    deadline = milliseconds(parent["evaluated_at"]) + 6000
    if phase == "after":
        time.sleep(max(0, deadline - runtime.clock.now_ms() + 30) / 1000)
        submitted, head = event(runtime, tx, "RECOVERY_FAILED")
        runtime.custody.append(submitted, head)
        assert runtime.custody.state(tx) == "RECOVERY_FAILED"
        receipt = witness_record(runtime.custody, digest(submitted))["receipt"]
        assert milliseconds(receipt["body"]["received_at"]) >= deadline
    else:
        submitted, head = event(runtime, tx, "RECOVERY_FAILED", at=timestamp(deadline + 1))
        config = _config(runtime.custody)
        gate = WitnessGate(runtime.custody, config)
        pending = gate._bind(submitted, head)
        time.sleep(max(0, deadline - runtime.clock.now_ms() - 1000) / 1000)
        pending["receipt"] = _receipt(config, submitted, pending["nonce"])
        observed = milliseconds(pending["receipt"]["body"]["received_at"])
        assert 0 < deadline + 1 - observed <= witness.manifest["future_tolerance_ms"]
        pending["status"] = "RECEIVED"
        replace_json(gate.pending_path, pending)
        with pytest.raises(ClosureError, match="WITNESS_GATE_RECOVERY_DEADLINE_NOT_OBSERVED"):
            runtime.custody.append(submitted, head)
        pending = read_json(runtime.custody.root / "witness" / "pending.json", "missing")
        assert milliseconds(pending["receipt"]["body"]["received_at"]) < deadline
        assert runtime.custody.state(tx) == "RECOVERY_REQUIRED"


@pytest.mark.parametrize("phase", ["before", "after", "immediate-baseline-drift"])
def test_child_recovery_failure_uses_actual_receipt_clock_and_preserves_immediate_failure(gated, phase):
    runtime, witness, _, deployment, _ = gated
    original = deployment.target("shop/api")
    upstream = urlsplit(original["base_url"])

    class FaultProxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def do_GET(self):
            self.forward()

        def do_PUT(self):
            self.forward()

        def forward(self):
            if self.server.observation_outage and self.path in {"/answer", "/config", "/other"}:
                self.server.outage_count += 1
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            else:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else None
                connection = http.client.HTTPConnection(upstream.hostname, upstream.port, timeout=5)
                headers = {
                    name: value
                    for name, value in self.headers.items()
                    if name.lower() not in {"host", "connection", "transfer-encoding"}
                }
                try:
                    connection.request(self.command, self.path, raw, headers)
                    response = connection.getresponse()
                    raw, status = response.read(), response.status
                finally:
                    connection.close()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), FaultProxy)
    proxy.daemon_threads = True
    proxy.observation_outage = False
    proxy.outage_count = 0
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    profile = dict(original, base_url="http://127.0.0.1:" + str(proxy.server_address[1]))
    replace_json(deployment.target_path("shop/api"), profile)  # operator enrollment BEFORE either contract
    try:
        tx, raw = "child-deadline", artifact(3, other="changed")
        runtime.propose(
            "shop/api",
            tx,
            raw,
            intent="Child deadline boundary",
            expect=expect_of(raw),
            duration_ms=WINDOW["duration_ms"],
            min_samples=WINDOW["min_samples"],
            max_clock_skew_ms=WINDOW["max_clock_skew_ms"],
            settle_ms=WINDOW["settle_ms"],
            recovery_deadline_ms=40000,
        )
        runtime.approve(tx)
        runtime.freeze(tx)
        runtime.baseline(tx)
        runtime.bind(tx)
        runtime.deploy(tx)
        runtime.observe(tx, phase="all")
        parent_result = runtime.close(tx)
        if parent_result["state"] == "OBSERVING":
            parent_result = runtime.close(tx)
        assert parent_result["verdict"] == "DISPROVEN"
        parent = runtime.custody.technical_packet(tx)
        child_id = tx + "/recovery"
        runtime.begin_recovery(tx)
        runtime.approve(child_id)
        runtime.freeze(child_id)
        runtime.baseline(child_id)
        runtime.bind(child_id)
        runtime.deploy(child_id)
        if phase == "immediate-baseline-drift":
            status, _ = runtime._client("shop/api", with_token=True).deploy(
                artifact(2), parent["payload"]["body"]["baseline_hash"], "injected-collateral-baseline-drift"
            )
            assert status == 200
        proxy.observation_outage = phase != "immediate-baseline-drift"
        runtime.observe(child_id, phase="all")
        child_result = runtime.close(child_id)
        if child_result["state"] == "OBSERVING":
            child_result = runtime.close(child_id)
        assert child_result["verdict"] == (
            "DISPROVEN" if phase == "immediate-baseline-drift" else "INDETERMINATE"
        )
        assert (proxy.outage_count > 0) == (phase != "immediate-baseline-drift")
        child = runtime._tx(child_id)
        deadline = milliseconds(parent["payload"]["body"]["evaluated_at"]) + 40000
        submitted, head = event(
            runtime,
            tx,
            "RECOVERY_FAILED",
            at=timestamp(deadline + 1) if phase == "before" else None,
            packet=child["verdict_packet"],
        )
        body = dict(
            submitted["payload"]["body"],
            recovery_contract=child["contract"],
            recovery_approval=child["approval"],
        )
        if phase == "after":
            time.sleep(max(0, deadline - runtime.clock.now_ms() + 30) / 1000)
        submitted = sign(
            runtime._identity("authority"),
            "ledger-event",
            body,
            timestamp(deadline + 1) if phase == "before" else runtime.clock.now(),
        )
        if phase == "before":
            config = _config(runtime.custody)
            gate = WitnessGate(runtime.custody, config)
            pending = gate._bind(submitted, head)
            time.sleep(max(0, deadline - runtime.clock.now_ms() - 1000) / 1000)
            pending["receipt"] = _receipt(config, submitted, pending["nonce"])
            observed = milliseconds(pending["receipt"]["body"]["received_at"])
            assert 0 < deadline + 1 - observed <= witness.manifest["future_tolerance_ms"]
            pending["status"] = "RECEIVED"
            replace_json(gate.pending_path, pending)
            with pytest.raises(ClosureError, match="WITNESS_GATE_RECOVERY_DEADLINE_NOT_OBSERVED"):
                runtime.custody.append(submitted, head)
            assert runtime.custody.state(tx) == "RECOVERY_REQUIRED"
        else:
            runtime.custody.append(submitted, head)
            assert runtime.custody.state(tx) == "RECOVERY_FAILED"
            record = witness_record(runtime.custody, digest(submitted))
            observed = milliseconds(record["receipt"]["body"]["received_at"])
            assert (observed < deadline) == (phase == "immediate-baseline-drift")
    finally:
        proxy.shutdown()
        proxy.server_close()
