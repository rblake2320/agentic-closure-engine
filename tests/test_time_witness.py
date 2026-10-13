"""Real deployed closure, separate signing service and durable reception/consumer journals.

Only clock-discontinuity tests override the clock function; outcomes/signatures/network/state
are real. Adversarial packet re-signing intentionally exercises a dishonest enrolled signer.
"""

import copy
import json
import os
import queue
import secrets
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from test_runtime_portable import proof_world  # noqa: F401

from closure_engine import time_witness as tw
from closure_engine.crypto import sign
from closure_engine.protocol import ClosureError, canonical, digest, milliseconds, timestamp
from closure_engine.runtime.files import create_json
from closure_engine.runtime.identities import load_identity


@pytest.fixture
def subject(proof_world):  # noqa: F811
    runtime, pin, _, _ = proof_world
    return runtime.closure("portable-real")["packet"], runtime.trust, pin, runtime


@pytest.fixture
def witness(tmp_path, subject):
    _, trust, pin, _ = subject
    root = tmp_path / "witness"
    init = tw.initialize(root, "independent-witness", trust, pin)
    return tw.Witness(root, init["expected_witness_hash"], pin)


def arguments(witness, subject, nonce):
    return {
        "expected_witness_hash": digest(witness.manifest),
        "authority_trust": subject[1],
        "expected_authority_hash": subject[2],
        "expected_nonce": nonce,
    }


def resign(subject, **changes):
    packet, _, _, runtime = subject
    body = copy.deepcopy(packet["payload"]["body"])
    body.update(changes)
    key = load_identity(runtime.deployment.role_root("authority"), "authority")
    return sign(key, "closure-packet", body, body["evaluated_at"])


def test_real_deployment_receipt_preserves_authority_packet_and_is_separate(witness, subject, tmp_path):
    packet = subject[0]
    original = canonical(packet)
    nonce = secrets.token_hex(32)
    receipt = witness.receive(packet, nonce)
    assert receipt["body"]["packet_hash"] == digest(packet)
    assert tw.verify_receipt(receipt, packet, witness.manifest, **arguments(witness, subject, nonce))
    tw.ConsumerJournal.initialize(tmp_path / "consumer.sqlite")
    result = tw.ConsumerJournal(tmp_path / "consumer.sqlite").consume(
        receipt, packet, witness.manifest, **arguments(witness, subject, nonce)
    )
    assert result["status"] == "WITNESSED"
    assert packet["payload"]["body"]["verdict"] == "PROVEN"
    assert canonical(packet) == original
    assert witness.manifest["public_key"] not in {k["public_key"] for k in subject[1].data["keys"]}


def test_signed_receipt_replay_refused_after_consumer_restart(witness, subject, tmp_path):
    nonce = secrets.token_hex(32)
    receipt = witness.receive(subject[0], nonce)
    path = tmp_path / "consumer.sqlite"
    tw.ConsumerJournal.initialize(path)
    tw.ConsumerJournal(path).consume(
        receipt, subject[0], witness.manifest, **arguments(witness, subject, nonce)
    )
    with pytest.raises(ClosureError, match="WITNESS_REPLAY_OR_REGRESSION"):
        tw.ConsumerJournal(path).consume(
            receipt, subject[0], witness.manifest, **arguments(witness, subject, nonce)
        )


def test_same_nonce_exact_retry_returns_same_receipt_without_advancing(witness, subject):
    nonce = secrets.token_hex(32)
    first = witness.receive(subject[0], nonce)
    assert witness.receive(subject[0], nonce) == first
    assert witness.checkpoint()["sequence"] == 1


def test_same_nonce_different_authentic_packet_refused(witness, subject):
    nonce = secrets.token_hex(32)
    witness.receive(subject[0], nonce)
    with pytest.raises(ClosureError, match="WITNESS_NONCE_REUSED"):
        witness.receive(resign(subject, transaction_id="dishonest-substitution"), nonce)


@pytest.mark.parametrize("change", ["witness-pin", "authority-pin", "key", "nonce", "signature", "packet"])
def test_tamper_and_enrollment_swap_refused(witness, subject, change):
    nonce = secrets.token_hex(32)
    receipt, manifest, packet = (
        witness.receive(subject[0], nonce),
        copy.deepcopy(witness.manifest),
        subject[0],
    )
    args = arguments(witness, subject, nonce)
    if change == "witness-pin":
        args["expected_witness_hash"] = digest(b"invented-root")
    elif change == "authority-pin":
        args["expected_authority_hash"] = digest(b"invented-authority")
    elif change == "key":
        manifest["public_key"] = secrets.token_hex(32)
    elif change == "nonce":
        args["expected_nonce"] = secrets.token_hex(32)
    elif change == "signature":
        receipt["signature"] = "00" * 64
    else:
        packet = resign(subject, transaction_id="different-authentic-subject")
    with pytest.raises(ClosureError):
        tw.verify_receipt(receipt, packet, manifest, **args)


def test_unenrolled_invented_authority_cannot_supply_packet(witness, subject):
    from closure_engine.crypto import Identity

    packet = subject[0]
    forged = sign(
        Identity.generate("authority", "invented-authority"),
        "closure-packet",
        packet["payload"]["body"],
        packet["payload"]["created_at"],
    )
    with pytest.raises(ClosureError, match="UNENROLLED_KEY"):
        witness.receive(forged, secrets.token_hex(32))


@pytest.mark.parametrize(
    "offset,code", [(120_000, "WITNESS_PACKET_FUTURE"), (-120_000, "WITNESS_PACKET_LATE")]
)
def test_enrolled_authority_cannot_future_date_or_backdate_against_witness(witness, subject, offset, code):
    changed = resign(subject, evaluated_at=timestamp(tw._now_ms() + offset))
    with pytest.raises(ClosureError, match=code):
        witness.receive(changed, secrets.token_hex(32))
    assert witness.checkpoint()["sequence"] == 0


def test_equal_clock_values_get_distinct_monotonic_sequences(witness, subject, monkeypatch):
    now = tw._now_ms()
    monkeypatch.setattr(tw, "_now_ms", lambda: now)
    first, second = [witness.receive(subject[0], secrets.token_hex(32)) for _ in range(2)]
    assert first["body"]["received_at"] == second["body"]["received_at"]
    assert second["body"]["sequence"] == first["body"]["sequence"] + 1
    assert second["body"]["previous_hash"] == digest(first)


def test_clock_regression_after_restart_refused(witness, subject, monkeypatch):
    first = witness.receive(subject[0], secrets.token_hex(32))
    at = milliseconds(first["body"]["received_at"])
    monkeypatch.setattr(tw, "_now_ms", lambda: at - 1)
    again = tw.Witness(witness.root, digest(witness.manifest), subject[2])
    with pytest.raises(ClosureError, match="WITNESS_CLOCK_REGRESSION"):
        again.receive(subject[0], secrets.token_hex(32))


def test_running_clock_jump_detected_before_issue(witness, subject, monkeypatch):
    now = tw._now_ms()
    monkeypatch.setattr(tw, "_now_ms", lambda: now + 10_000)
    with pytest.raises(ClosureError, match="WITNESS_CLOCK_DISCONTINUITY"):
        witness.receive(subject[0], secrets.token_hex(32))


def test_receipt_age_and_future_checks_use_consumer_clock(witness, subject, monkeypatch):
    nonce = secrets.token_hex(32)
    receipt = witness.receive(subject[0], nonce)
    at = milliseconds(receipt["body"]["received_at"])
    monkeypatch.setattr(tw, "_now_ms", lambda: at + 60_001)
    with pytest.raises(ClosureError, match="WITNESS_RECEIPT_STALE"):
        tw.verify_receipt(receipt, subject[0], witness.manifest, **arguments(witness, subject, nonce))
    monkeypatch.setattr(tw, "_now_ms", lambda: at - 2_001)
    with pytest.raises(ClosureError, match="WITNESS_RECEIPT_FUTURE"):
        tw.verify_receipt(receipt, subject[0], witness.manifest, **arguments(witness, subject, nonce))


def test_late_witness_does_not_rewrite_historical_proven(witness, subject, monkeypatch):
    original = canonical(subject[0])
    at = milliseconds(subject[0]["payload"]["body"]["evaluated_at"]) + 60_001
    monkeypatch.setattr(tw, "_now_ms", lambda: at)
    again = tw.Witness(witness.root, digest(witness.manifest), subject[2])
    with pytest.raises(ClosureError, match="WITNESS_PACKET_LATE"):
        again.receive(subject[0], secrets.token_hex(32))
    assert canonical(subject[0]) == original
    assert subject[0]["payload"]["body"]["verdict"] == "PROVEN"


def test_external_checkpoint_detects_truncated_signed_history(witness, subject):
    witness.receive(subject[0], secrets.token_hex(32))
    checkpoint = witness.checkpoint()
    with sqlite3.connect(witness.db_path) as db:
        db.execute("DELETE FROM receipts")
    with pytest.raises(ClosureError, match="WITNESS_CHECKPOINT_MISMATCH"):
        tw.Witness(witness.root, digest(witness.manifest), subject[2], expected_checkpoint=checkpoint)


def test_missing_database_is_not_reconstructed(witness, subject):
    witness.db_path.unlink()
    with pytest.raises(ClosureError, match="WITNESS_STORAGE_UNAVAILABLE"):
        tw.Witness(witness.root, digest(witness.manifest), subject[2])
    assert not witness.db_path.exists()


def test_modified_signed_history_refused_before_issue(witness, subject):
    receipt = witness.receive(subject[0], secrets.token_hex(32))
    receipt["body"]["received_at"] = timestamp(tw._now_ms() + 1)
    with sqlite3.connect(witness.db_path) as db:
        db.execute("UPDATE receipts SET envelope=?", (canonical(receipt),))
    with pytest.raises(ClosureError, match="WITNESS_SIGNATURE_INVALID"):
        witness.receive(subject[0], secrets.token_hex(32))


def test_concurrent_exact_retry_has_one_receipt(witness, subject):
    nonce = secrets.token_hex(32)
    with ThreadPoolExecutor(max_workers=6) as pool:
        receipts = list(pool.map(lambda _: witness.receive(subject[0], nonce), range(12)))
    assert len({digest(receipt) for receipt in receipts}) == 1
    assert witness.checkpoint()["sequence"] == 1


def _process(witness, subject):
    command = [sys.executable]
    if os.environ.get("TIME_WITNESS_INSTALLED") == "1":
        command.append("-I")
    command.extend(
        [
            "-m",
            "closure_engine.time_witness",
            "serve",
            "--root",
            str(witness.root),
            "--expected-witness-hash",
            digest(witness.manifest),
            "--expected-authority-hash",
            subject[2],
            "--port",
            "0",
        ]
    )
    child_env = dict(os.environ)
    if "-I" not in command:
        child_env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=child_env
    )
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    try:
        line = lines.get(timeout=10)
        message = json.loads(line)
        assert message["status"] == "LISTENING", message
        return process, "http://127.0.0.1:" + str(message["port"])
    except BaseException:
        process.kill()
        process.wait(timeout=5)
        raise


def test_real_separate_process_restart_receipt_and_replay(witness, subject, tmp_path):
    token = (witness.root / "client.token").read_text()
    nonce = secrets.token_hex(32)
    process, url = _process(witness, subject)
    try:
        receipt = tw.request_receipt(url, token, subject[0], nonce)
        with pytest.raises(ClosureError, match="AUTHENTICATION_REQUIRED"):
            tw.request_receipt(url, "forged", subject[0], secrets.token_hex(32))
        with pytest.raises(ClosureError, match="WITNESS_REQUEST_INVALID"):
            tw.ServiceClient(url, token).call(
                "POST",
                "/receipts",
                {"packet": subject[0], "nonce": secrets.token_hex(32), "now": "2099-01-01T00:00:00Z"},
            )
    finally:
        process.kill()  # real abrupt service termination after durable commit
        process.wait(timeout=5)
    process, url = _process(witness, subject)
    try:
        assert tw.request_receipt(url, token, subject[0], nonce) == receipt
        next_receipt = tw.request_receipt(url, token, subject[0], secrets.token_hex(32))
        assert next_receipt["body"]["sequence"] == 2
        assert next_receipt["body"]["previous_hash"] == digest(receipt)
        create_json(tmp_path / "public-receipt.json", receipt)
        assert tw.verify_receipt(receipt, subject[0], witness.manifest, **arguments(witness, subject, nonce))
    finally:
        process.kill()
        process.wait(timeout=5)


def test_shipped_operator_cli_enroll_request_consume_and_checkpoint(subject, tmp_path):
    prefix = [sys.executable]
    env = dict(os.environ)
    if os.environ.get("TIME_WITNESS_INSTALLED") == "1":
        prefix.append("-I")
    else:
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    prefix.extend(["-m", "closure_engine.time_witness"])

    def cli(*args, expected=0):
        result = subprocess.run(prefix + list(args), capture_output=True, text=True, env=env, timeout=20)
        assert result.returncode == expected, result.stdout + result.stderr
        return json.loads(result.stdout)

    root, trust_file = tmp_path / "cli-witness", tmp_path / "operator-trust.json"
    packet_file, receipt_file, journal = (
        tmp_path / "packet.json",
        tmp_path / "receipt.json",
        tmp_path / "journal.db",
    )
    create_json(trust_file, subject[1].data)
    create_json(packet_file, subject[0])
    enrolled = cli(
        "init",
        "--root",
        str(root),
        "--issuer",
        "cli-site",
        "--authority-trust",
        str(trust_file),
        "--expected-authority-hash",
        subject[2],
    )
    witness = tw.Witness(root, enrolled["expected_witness_hash"], subject[2])
    cli("journal-init", "--journal", str(journal))
    process, url = _process(witness, subject)
    try:
        nonce = secrets.token_hex(32)
        requested = cli(
            "request",
            "--url",
            url,
            "--token-file",
            str(root / "client.token"),
            "--packet",
            str(packet_file),
            "--nonce",
            nonce,
            "--out",
            str(receipt_file),
        )
        assert requested["receipt_hash"] == digest(tw.read_json(receipt_file))
        verification = [
            "verify",
            "--receipt",
            str(receipt_file),
            "--packet",
            str(packet_file),
            "--manifest",
            str(root / "manifest.json"),
            "--expected-witness-hash",
            enrolled["expected_witness_hash"],
            "--authority-trust",
            str(trust_file),
            "--expected-authority-hash",
            subject[2],
            "--nonce",
            nonce,
            "--journal",
            str(journal),
        ]
        assert cli(*verification)["status"] == "WITNESSED"
        assert cli(*verification, expected=2)["error"] == "WITNESS_REPLAY_OR_REGRESSION"
        checkpoint = cli(
            "checkpoint",
            "--root",
            str(root),
            "--expected-witness-hash",
            enrolled["expected_witness_hash"],
            "--expected-authority-hash",
            subject[2],
        )
        assert checkpoint["sequence"] == 1
        token = (root / "client.token").read_text()
        assert token not in canonical(enrolled).decode()
        assert token not in canonical(checkpoint).decode()
    finally:
        process.kill()
        process.wait(timeout=5)


def test_remote_plaintext_transport_refused(witness, subject):
    with pytest.raises(ClosureError, match="WITNESS_TLS_REQUIRED_FOR_NON_LOOPBACK"):
        tw.make_server(witness, host="0.0.0.0")
    with pytest.raises(ClosureError, match="WITNESS_TLS_REQUIRED_FOR_NON_LOOPBACK"):
        tw.request_receipt("http://customer.example:8790", "never-sent", subject[0], secrets.token_hex(32))


def test_shared_clock_is_not_independent_truth_control(witness, subject, monkeypatch):
    """A compromised shared time source before both processes start is NOT detectable by signatures.

    This green limitation control ensures documentation cannot claim trusted/hardware UTC.
    """
    future = tw._now_ms() + 86_400_000
    forged_time = resign(subject, evaluated_at=timestamp(future))
    monkeypatch.setattr(tw, "_now_ms", lambda: future)
    again = tw.Witness(witness.root, digest(witness.manifest), subject[2])
    nonce = secrets.token_hex(32)
    receipt = again.receive(forged_time, nonce)
    assert tw.verify_receipt(receipt, forged_time, again.manifest, **arguments(again, subject, nonce))
    assert receipt["body"]["evaluated_at"] == timestamp(future)


def authority_event(subject, *, state="RECOVERY_FAILED", at=None, role="authority"):
    runtime = subject[3]
    packet = subject[0]["payload"]["body"]
    body = {
        "event_id": "witness-bound-event",
        "transaction_id": packet["transaction_id"],
        "contract_hash": packet["contract_hash"],
        "sequence": 20,
        "previous_hash": packet["ledger_head"],
        "state": state,
        "refs": [],
        "packet": None,
        "binding": None,
        "receipt": None,
        "recovery_contract": None,
        "recovery_approval": None,
        "risk": None,
    }
    # This is a signer-adversary primitive probe, not an admitted ledger transition.
    return sign(
        load_identity(runtime.deployment.role_root(role), role),
        "ledger-event",
        body,
        timestamp(at if at is not None else tw._now_ms()),
    )


def test_authority_recovery_failed_event_witness_is_purpose_bound(witness, subject, tmp_path):
    event, nonce = authority_event(subject), secrets.token_hex(32)
    receipt = witness.receive(event, nonce)
    assert receipt["body"]["subject_purpose"] == "ledger-event"
    assert receipt["body"]["packet_hash"] == digest(event)
    args = arguments(witness, subject, nonce)
    with pytest.raises(ClosureError, match="WITNESS_SUBJECT_PURPOSE_MISMATCH"):
        tw.verify_receipt(receipt, event, witness.manifest, **args)
    args["expected_subject_purpose"] = "ledger-event"
    tw.ConsumerJournal.initialize(tmp_path / "event-journal.sqlite")
    assert (
        tw.ConsumerJournal(tmp_path / "event-journal.sqlite").consume(
            receipt, event, witness.manifest, **args
        )["status"]
        == "WITNESSED"
    )
    assert witness.checkpoint()["sequence"] == 1


def test_real_admitted_proven_event_is_witnessed_without_rewriting_ledger(witness, subject):
    runtime = subject[3]
    page = runtime.audit_export()
    event = next(e for e in page["events"] if e["payload"]["body"]["state"] == "PROVEN")
    before = canonical(event)
    nonce = secrets.token_hex(32)
    receipt = witness.receive(event, nonce)
    assert receipt["body"]["packet_hash"] == digest(event)
    tw.verify_receipt(
        receipt,
        event,
        witness.manifest,
        **arguments(witness, subject, nonce),
        expected_subject_purpose="ledger-event",
    )
    assert canonical(event) == before
    after = runtime.audit_export()
    # Export signs a fresh checkpoint envelope on each call; compare its immutable chain body.
    assert after["events"] == page["events"]
    assert after["checkpoint"]["payload"]["body"] == page["checkpoint"]["payload"]["body"]


@pytest.mark.parametrize("offset,code", [(120_000, "WITNESS_EVENT_FUTURE"), (-120_000, "WITNESS_EVENT_LATE")])
def test_signer_future_recovery_failed_event_refused(witness, subject, offset, code):
    event = authority_event(subject, at=tw._now_ms() + offset)
    with pytest.raises(ClosureError, match=code):
        witness.receive(event, secrets.token_hex(32))
    assert witness.checkpoint()["sequence"] == 0


def test_actor_cannot_obtain_authority_event_witness(witness, subject):
    with pytest.raises(ClosureError, match="WITNESS_EVENT_ROLE_DENIED"):
        witness.receive(authority_event(subject, role="actor"), secrets.token_hex(32))


@pytest.mark.parametrize("subject_value", [{"payload": []}, {"payload": {"purpose": []}}, None])
def test_invalid_subject_is_contained(witness, subject_value):
    with pytest.raises(ClosureError, match="WITNESS_SUBJECT_PURPOSE_DENIED"):
        witness.receive(subject_value, secrets.token_hex(32))


def test_closure_receipt_cannot_be_consumed_as_ledger_event(witness, subject):
    nonce = secrets.token_hex(32)
    receipt = witness.receive(subject[0], nonce)
    with pytest.raises(ClosureError, match="WITNESS_SUBJECT_PURPOSE_MISMATCH"):
        tw.verify_receipt(
            receipt,
            subject[0],
            witness.manifest,
            **arguments(witness, subject, nonce),
            expected_subject_purpose="ledger-event",
        )


def test_legacy_closure_only_receipt_and_manifest_remain_verifiable(witness, subject):
    nonce = secrets.token_hex(32)
    receipt = witness.receive(subject[0], nonce)
    manifest = copy.deepcopy(witness.manifest)
    manifest.pop("subject_purposes")
    receipt["body"].pop("subject_purpose")
    receipt["body"]["manifest_hash"] = digest(manifest)
    receipt["signature"] = witness.key.private_key.sign(tw.DOMAIN + canonical(receipt["body"])).hex()
    original = canonical(receipt)
    args = arguments(witness, subject, nonce)
    args["expected_witness_hash"] = digest(manifest)
    assert tw.verify_receipt(receipt, subject[0], manifest, **args)
    assert canonical(receipt) == original
    with pytest.raises(ClosureError, match="WITNESS_SUBJECT_PURPOSE_DENIED"):
        tw._subject(authority_event(subject), subject[1], manifest, tw._now_ms())
