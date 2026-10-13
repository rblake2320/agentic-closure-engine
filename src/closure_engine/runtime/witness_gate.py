"""Opt-in custody enforcement of separately pinned temporal witness receipts.

No generic signing or caller-selected clock. The privileged consumption journal commits its
custodian signature in the same SQLite transaction as its unique replay cursor. A pending
operation is bound before network effects; exact retries reconcile that signed record.
"""

import os
import secrets
import sqlite3
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..contracts import freeze
from ..ledger import ROLES as EVENT_ROLES
from ..protocol import MAX_BYTES, ClosureError, canonical, digest, milliseconds, strict_loads
from ..recovery import recovery_status
from ..time_witness import ConsumerJournal, _enrollment, _signature, _subject, verify_receipt
from .files import create_exclusive, create_json, read_json, replace_json
from .rpc import _RefuseRedirect

CONFIG = "witness-gate.json"
CONFIG_DOMAIN = b"ACE/witness-gate-config/v1\x00"
CONSUMPTION_DOMAIN = b"ACE/witness-consumption/v1\x00"
CONSUMPTION_GENESIS = digest(b"ACE/witness-consumption/v1/genesis")


def _signed(identity, domain, body):
    payload = {"version": "v1", "issuer": identity.issuer, "key_id": identity.key_id, "body": body}
    return {
        "algorithm": "Ed25519",
        "payload": payload,
        "signature": identity.private_key.sign(domain + canonical(payload)).hex(),
    }


def _verify(envelope, domain, trust):
    try:
        if set(envelope) != {"algorithm", "payload", "signature"} or envelope["algorithm"] != "Ed25519":
            raise ValueError()
        payload = envelope["payload"]
        if set(payload) != {"version", "issuer", "key_id", "body"} or payload["version"] != "v1":
            raise ValueError()
        record = trust.record(payload["key_id"])
        if record["role"] != "custodian" or record["issuer"] != payload["issuer"]:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["public_key"])).verify(
            bytes.fromhex(envelope["signature"]), domain + canonical(payload)
        )
        return payload["body"]
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ClosureError("WITNESS_GATE_SIGNATURE_INVALID") from exc


def _config(custody):
    path = custody.deployment.role_root("operator") / CONFIG
    marker = custody.root / "witness" / "required.json"
    try:
        path.stat()
        configured = True
    except FileNotFoundError:
        configured = False
    except OSError as exc:
        raise ClosureError("WITNESS_GATE_CONFIG_UNREADABLE") from exc
    try:
        marker.stat()
        required = True
    except FileNotFoundError:
        required = False
    except OSError as exc:
        raise ClosureError("WITNESS_GATE_REQUIRED_MARKER_UNREADABLE") from exc
    if not configured and not required:
        return None
    if not configured:
        raise ClosureError("WITNESS_GATE_CONFIG_MISSING")
    if not required:
        # Latch REQUIRED before parsing even the first malformed/unreadable profile.
        # A failed enrollment must not become implicit normal mode on the next restart.
        initial = {"config_hash": None, "authority_trust_hash": custody.trust.hash}
        try:
            create_json(marker, _signed(custody._custodian(), CONFIG_DOMAIN, initial), private=True)
        except ClosureError as exc:
            if exc.code != "STATE_ALREADY_EXISTS":
                raise
        required = True
    try:
        value = read_json(path, "WITNESS_GATE_CONFIG_MISSING")
        fields = {
            "version",
            "endpoint",
            "manifest",
            "expected_witness_hash",
            "expected_authority_hash",
            "token_file",
            "ca_file",
            "timeout_ms",
        }
        if not isinstance(value, dict) or set(value) != fields or value["version"] != "v1":
            raise ClosureError("WITNESS_GATE_CONFIG_INVALID")
        _enrollment(
            value["manifest"], value["expected_witness_hash"], custody.trust, value["expected_authority_hash"]
        )
        if value["manifest"].get("subject_purposes") != ["closure-packet", "ledger-event"]:
            raise ClosureError("WITNESS_GATE_EVENT_CAPABILITY_MISSING")
        parts = urlsplit(value["endpoint"])
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise ClosureError("WITNESS_GATE_HTTPS_REQUIRED")
        if type(value["timeout_ms"]) is not int or not 100 <= value["timeout_ms"] <= 30_000:
            raise ClosureError("WITNESS_GATE_CONFIG_INVALID")
        for field in ("token_file", "ca_file"):
            if not isinstance(value[field], str) or not Path(value[field]).is_absolute():
                raise ClosureError("WITNESS_GATE_PRIVATE_REFERENCE_INVALID")
            if not Path(value[field]).is_file():
                raise ClosureError("WITNESS_GATE_PRIVATE_REFERENCE_MISSING")
        frozen = {"config_hash": digest(value), "authority_trust_hash": custody.trust.hash}
        if required:
            pinned = _verify(
                read_json(marker, "WITNESS_GATE_REQUIRED_MARKER_MISSING"), CONFIG_DOMAIN, custody.trust
            )
            if pinned == {"config_hash": None, "authority_trust_hash": custody.trust.hash}:
                replace_json(marker, _signed(custody._custodian(), CONFIG_DOMAIN, frozen))
            elif pinned != frozen:
                raise ClosureError("WITNESS_GATE_CONFIG_CHANGED")
        else:
            create_json(marker, _signed(custody._custodian(), CONFIG_DOMAIN, frozen), private=True)
        return value
    except OSError as exc:
        raise ClosureError("WITNESS_GATE_CONFIG_UNREADABLE") from exc
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, ClosureError):
            raise
        raise ClosureError("WITNESS_GATE_CONFIG_INVALID") from exc


def check_witness_configuration(custody):
    """Startup check and sticky enrollment. Missing/malformed opted-in policy cannot become off."""
    _config(custody)


@contextmanager
def _exclusive(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    locked = False
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"0")
            os.fsync(fd)
        until = time.monotonic() + 15
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() > until:
                    raise ClosureError("WITNESS_GATE_BUSY") from None
                time.sleep(0.025)
        yield
    finally:
        if locked:
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _receipt(config, subject, nonce):
    try:
        token = Path(config["token_file"]).read_text().strip()
        if not token or len(token) > 512 or any(c.isspace() for c in token):
            raise ClosureError("WITNESS_GATE_CREDENTIAL_INVALID")
        context = ssl.create_default_context(cafile=config["ca_file"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = request.build_opener(
            request.ProxyHandler({}), _RefuseRedirect(), request.HTTPSHandler(context=context)
        )
        call = request.Request(
            config["endpoint"].rstrip("/") + "/receipts",
            method="POST",
            data=canonical({"packet": subject, "nonce": nonce}),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        with opener.open(call, timeout=config["timeout_ms"] / 1000) as response:
            raw = response.read(MAX_BYTES + 1)
        return strict_loads(raw)
    except error.HTTPError as exc:
        try:
            code = strict_loads(exc.read(4096)).get("error")
        except (ClosureError, AttributeError):
            code = None
        # Do not relay arbitrary server error text or private URL/credential material.
        if isinstance(code, str) and code in {
            "WITNESS_EVENT_FUTURE",
            "WITNESS_EVENT_LATE",
            "WITNESS_PACKET_FUTURE",
            "WITNESS_PACKET_LATE",
            "WITNESS_NONCE_REUSED",
            "WITNESS_CLOCK_REGRESSION",
            "WITNESS_CLOCK_DISCONTINUITY",
        }:
            raise ClosureError(code) from exc
        raise ClosureError("WITNESS_GATE_RECEIPT_UNAVAILABLE") from exc
    except (OSError, ssl.SSLError, error.URLError, UnicodeError) as exc:
        raise ClosureError("WITNESS_GATE_RECEIPT_UNAVAILABLE") from exc


class SignedConsumerJournal(ConsumerJournal):
    """Custodian-sealed anti-replay log; journal row and proof are one durable commit."""

    def __init__(self, path, custody):
        super().__init__(path)
        self.custody = custody
        marker = self.path.with_suffix(".initialized.json")
        if not self.path.exists() and not marker.exists():
            create_exclusive(self.path, b"", private=True)
            with self._db() as db:
                db.execute(
                    "CREATE TABLE consumed (consumption_index INTEGER PRIMARY KEY, manifest_hash TEXT, "
                    "nonce TEXT, witness_sequence INTEGER, proof BLOB, UNIQUE(manifest_hash,nonce), "
                    "UNIQUE(manifest_hash,witness_sequence))"
                )
            create_json(
                marker, {"genesis": CONSUMPTION_GENESIS, "trust_hash": custody.trust.hash}, private=True
            )
        elif not self.path.exists() or not marker.exists():
            raise ClosureError("WITNESS_GATE_JOURNAL_MISSING")

    @contextmanager
    def _db(self):
        db = None
        try:
            db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=15)
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        except sqlite3.Error as exc:
            raise ClosureError("WITNESS_GATE_JOURNAL_INVALID") from exc
        finally:
            if db is not None:
                db.close()

    def _rows(self, db):
        index, head, last = 0, CONSUMPTION_GENESIS, {}
        records = {}
        for row_index, manifest, nonce, sequence, raw in db.execute(
            "SELECT * FROM consumed ORDER BY consumption_index"
        ):
            proof = strict_loads(raw)
            body = _verify(proof, CONSUMPTION_DOMAIN, self.custody.trust)
            fields = {
                "consumption_index",
                "previous_hash",
                "manifest_hash",
                "nonce",
                "witness_sequence",
                "receipt_hash",
                "subject_hash",
                "subject_purpose",
                "event_hash",
                "expected_head",
                "config_hash",
                "consumed_at",
            }
            if not isinstance(body, dict) or set(body) != fields:
                raise ClosureError("WITNESS_GATE_JOURNAL_INVALID")
            if (
                row_index != index + 1
                or body.get("consumption_index") != row_index
                or body.get("previous_hash") != head
                or body.get("manifest_hash") != manifest
                or body.get("nonce") != nonce
                or body.get("witness_sequence") != sequence
                or type(sequence) is not int
                or sequence <= last.get(manifest, 0)
            ):
                raise ClosureError("WITNESS_GATE_JOURNAL_INVALID")
            milliseconds(body["consumed_at"])
            last[manifest] = sequence
            index, head = row_index, digest(proof)
            records[(manifest, nonce)] = proof
        return index, head, last, records

    def find(self, manifest_hash, nonce):
        with self._db() as db:
            return self._rows(db)[3].get((manifest_hash, nonce))

    def consume_bound(self, receipt, subject, config, pending):
        body = verify_receipt(
            receipt,
            subject,
            config["manifest"],
            expected_witness_hash=config["expected_witness_hash"],
            authority_trust=self.custody.trust,
            expected_authority_hash=config["expected_authority_hash"],
            expected_nonce=pending["nonce"],
            expected_subject_purpose=pending["subject_purpose"],
        )
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            index, head, last, rows = self._rows(db)
            if (body["manifest_hash"], body["nonce"]) in rows or body["sequence"] <= last.get(
                body["manifest_hash"], 0
            ):
                raise ClosureError("WITNESS_REPLAY_OR_REGRESSION")
            proof_body = {
                "consumption_index": index + 1,
                "previous_hash": head,
                "manifest_hash": body["manifest_hash"],
                "nonce": body["nonce"],
                "witness_sequence": body["sequence"],
                "receipt_hash": digest(receipt),
                "subject_hash": digest(subject),
                "subject_purpose": pending["subject_purpose"],
                "event_hash": pending["event_hash"],
                "expected_head": pending["expected_head"],
                "config_hash": pending["config_hash"],
                "consumed_at": self.custody.clock.now(),
            }
            proof = _signed(self.custody._custodian(), CONSUMPTION_DOMAIN, proof_body)
            db.execute(
                "INSERT INTO consumed VALUES (?,?,?,?,?)",
                (index + 1, body["manifest_hash"], body["nonce"], body["sequence"], canonical(proof)),
            )
        return proof


class WitnessGate:
    def __init__(self, custody, config):
        self.custody, self.config = custody, config
        self.root = custody.root / "witness"
        self.pending_path = self.root / "pending.json"
        self.journal = SignedConsumerJournal(self.root / "consumed.sqlite", custody)

    def _pending(self):
        value = read_json(self.pending_path, "WITNESS_GATE_PENDING_MISSING")
        fields = {
            "version",
            "status",
            "event",
            "event_hash",
            "expected_head",
            "config_hash",
            "subject",
            "subject_purpose",
            "nonce",
            "receipt",
            "consumption",
        }
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value["version"] != "v1"
            or (value["status"] not in {"PREPARED", "RECEIVED", "CONSUMED", "COMPLETE", "QUARANTINED"})
        ):
            raise ClosureError("WITNESS_GATE_PENDING_INVALID")
        if not isinstance(value["nonce"], str) or len(value["nonce"]) != 64:
            raise ClosureError("WITNESS_GATE_PENDING_INVALID")
        try:
            bytes.fromhex(value["nonce"])
        except ValueError as exc:
            raise ClosureError("WITNESS_GATE_PENDING_INVALID") from exc
        if digest(value["event"]) != value["event_hash"]:
            raise ClosureError("WITNESS_GATE_PENDING_INVALID")
        return value

    def _admitted(self, event):
        body = event["payload"]["body"]
        page = self.custody.ledger.audit_export(body["sequence"], 1)
        return bool(page["events"] and canonical(page["events"][0]) == canonical(event))

    def _recovery_deadline(self, pending):
        subject = pending["subject"]
        if subject["payload"]["purpose"] != "ledger-event":
            return
        body = subject["payload"]["body"]
        if body["state"] != "RECOVERY_FAILED":
            return
        receipt = _signature(pending["receipt"], self.config["manifest"])
        parent = self.custody.ledger.technical_packet(body["transaction_id"])
        if parent is None:
            raise ClosureError("WITNESS_GATE_RECOVERY_PARENT_MISSING")
        inputs = strict_loads(self.custody.store.get(parent["payload"]["body"]["inputs_hash"]))
        child = None
        if body["packet"] is not None:
            if body["recovery_contract"] is None or body["recovery_approval"] is None:
                raise ClosureError("RECOVERY_CONTRACT_REQUIRED")
            child = freeze(body["recovery_contract"], body["recovery_approval"], self.custody.trust)
        result = recovery_status(
            parent,
            child,
            body["packet"],
            self.custody.trust,
            milliseconds(receipt["received_at"]),
            inputs["contract"]["recovery"]["deadline_ms"],
            store=self.custody.store,
        )
        if result["state"] != "RECOVERY_FAILED":
            code = (
                "WITNESS_GATE_RECOVERY_DEADLINE_NOT_OBSERVED"
                if result["state"] == "RECOVERY_REQUIRED"
                else "WITNESS_GATE_RECOVERY_FAILURE_NOT_OBSERVED"
            )
            raise ClosureError(code)

    def _bind(self, event, expected_head):
        event_hash, config_hash = digest(event), digest(self.config)
        previous = self._pending() if self.pending_path.exists() else None
        if (
            previous
            and previous["status"] not in {"COMPLETE", "QUARANTINED"}
            and (previous["event_hash"] != event_hash or previous["expected_head"] != expected_head)
        ):
            raise ClosureError("WITNESS_GATE_PENDING_CONFLICT")
        if previous and previous["event_hash"] == event_hash:
            if (
                previous["event"] != event
                or previous["expected_head"] != expected_head
                or previous["config_hash"] != config_hash
                or previous["status"] == "QUARANTINED"
            ):
                raise ClosureError("WITNESS_GATE_PENDING_CONFLICT")
            body = event["payload"]["body"]
            subject = (
                self.custody.ledger.technical_packet(body["transaction_id"])
                if body["state"] == "ACCEPTED"
                else event
            )
            if (
                subject is None
                or previous["subject"] != subject
                or previous["subject_purpose"] != subject["payload"]["purpose"]
            ):
                raise ClosureError("WITNESS_GATE_PENDING_INVALID")
            return previous
        if self._admitted(event):
            return None  # historical exact retry: do not invent retrospective witnessed assurance
        snapshot = self.custody.ledger.snapshot()
        body = event["payload"]["body"]
        if (
            snapshot["head"] != expected_head
            or body["previous_hash"] != expected_head
            or (body["sequence"] != snapshot["sequence"] + 1)
        ):
            raise ClosureError("STALE_LEDGER_HEAD")
        if body["state"] == "ACCEPTED":
            subject = snapshot["packets"].get(body["transaction_id"])
            if subject is None or subject["payload"]["body"]["verdict"] != "PROVEN":
                raise ClosureError("WITNESS_GATE_CLOSURE_NOT_ADMITTED")
        else:
            subject = event
        pending = {
            "version": "v1",
            "status": "PREPARED",
            "event": event,
            "event_hash": event_hash,
            "expected_head": expected_head,
            "config_hash": config_hash,
            "subject": subject,
            "subject_purpose": subject["payload"]["purpose"],
            "nonce": secrets.token_hex(32),
            "receipt": None,
            "consumption": None,
        }
        replace_json(self.pending_path, pending)
        return pending

    def prepare(self, event, expected_head):
        pending = self._bind(event, expected_head)
        if pending is None:
            return None
        if not self._admitted(event) and self.custody.ledger.head != expected_head:
            pending["status"] = "QUARANTINED"
            replace_json(self.pending_path, pending)
            raise ClosureError("WITNESS_GATE_PENDING_HEAD_CONFLICT")
        proof = self.journal.find(self.config["expected_witness_hash"], pending["nonce"])
        receipt = pending["receipt"]
        if proof is not None:
            if receipt is None:
                raise ClosureError("WITNESS_GATE_PENDING_INVALID")
            proof_body = _verify(proof, CONSUMPTION_DOMAIN, self.custody.trust)
            expected = {
                "event_hash": pending["event_hash"],
                "expected_head": pending["expected_head"],
                "subject_hash": digest(pending["subject"]),
                "subject_purpose": pending["subject_purpose"],
                "receipt_hash": digest(receipt),
                "config_hash": pending["config_hash"],
            }
            if any(proof_body.get(k) != v for k, v in expected.items()):
                raise ClosureError("WITNESS_GATE_PENDING_INVALID")
            self._recovery_deadline(pending)
        else:
            if pending["status"] in {"CONSUMED", "COMPLETE"} or self._admitted(event):
                raise ClosureError("WITNESS_GATE_CONSUMPTION_MISSING")
            if receipt is None:
                receipt = _receipt(self.config, pending["subject"], pending["nonce"])
                verify_receipt(
                    receipt,
                    pending["subject"],
                    self.config["manifest"],
                    expected_witness_hash=self.config["expected_witness_hash"],
                    authority_trust=self.custody.trust,
                    expected_authority_hash=self.config["expected_authority_hash"],
                    expected_nonce=pending["nonce"],
                    expected_subject_purpose=pending["subject_purpose"],
                )
                pending["receipt"], pending["status"] = receipt, "RECEIVED"
                replace_json(self.pending_path, pending)
            self._recovery_deadline(pending)
            proof = self.journal.consume_bound(receipt, pending["subject"], self.config, pending)
        pending["consumption"], pending["status"] = proof, "CONSUMED"
        replace_json(self.pending_path, pending)
        record = {
            "version": "v1",
            "event": event,
            "subject": pending["subject"],
            "receipt": receipt,
            "consumption": proof,
            "manifest": self.config["manifest"],
            "config_hash": pending["config_hash"],
        }
        path = self.root / "receipts" / (pending["event_hash"].split(":")[1] + ".json")
        if path.exists():
            if read_json(path, "WITNESS_GATE_RECORD_MISSING") != record:
                raise ClosureError("WITNESS_GATE_RECORD_CONFLICT")
        else:
            create_json(path, record)
        # Operator profile must still be the exact required policy after the network round trip.
        if digest(_config(self.custody)) != pending["config_hash"]:
            raise ClosureError("WITNESS_GATE_CONFIG_CHANGED")
        return pending

    def complete(self, pending):
        if pending is not None:
            if not self._admitted(pending["event"]):
                raise ClosureError("WITNESS_GATE_ADMISSION_MISSING")
            pending["status"] = "COMPLETE"
            replace_json(self.pending_path, pending)
            replace_json(self.root / "operations" / (pending["event_hash"].split(":")[1] + ".json"), pending)


@contextmanager
def witness_scope(custody, event, expected_head):
    role = custody.trust.record(event["payload"]["key_id"])["role"]
    body = event["payload"]["body"]
    if role != "authority" and body["state"] != "ACCEPTED":
        yield
        return
    config = _config(custody)
    if config is None:
        yield
        return
    if role not in EVENT_ROLES[body["state"]]:
        raise ClosureError("STATE_AUTHORITY_DENIED")
    with _exclusive(custody.root / "witness" / "gate.lock"):
        gate = WitnessGate(custody, config)
        pending = gate.prepare(event, expected_head)
        yield
        gate.complete(pending)


def witness_record(custody, event_hash):
    """Read-only retained public sidecar, authenticated against custody and the actual ledger."""
    if (
        not isinstance(event_hash, str)
        or len(event_hash) != 71
        or not event_hash.startswith("sha256:")
        or any(c not in "0123456789abcdef" for c in event_hash[7:])
    ):
        raise ClosureError("INVALID_HASH")
    try:
        bytes.fromhex(event_hash[7:])
    except ValueError as exc:
        raise ClosureError("INVALID_HASH") from exc
    record = read_json(
        custody.root / "witness" / "receipts" / (event_hash[7:] + ".json"), "WITNESS_GATE_RECORD_UNAVAILABLE"
    )
    if (
        not isinstance(record, dict)
        or record.get("version") != "v1"
        or set(record)
        != {
            "version",
            "event",
            "subject",
            "receipt",
            "consumption",
            "manifest",
            "config_hash",
        }
    ):
        raise ClosureError("WITNESS_GATE_RECORD_INVALID")
    proof = _verify(record["consumption"], CONSUMPTION_DOMAIN, custody.trust)
    if (
        digest(record["event"]) != event_hash
        or proof.get("event_hash") != event_hash
        or proof.get("config_hash") != record["config_hash"]
        or (
            proof.get("subject_hash") != digest(record["subject"])
            or proof.get("receipt_hash") != digest(record["receipt"])
        )
    ):
        raise ClosureError("WITNESS_GATE_RECORD_INVALID")
    _enrollment(
        record["manifest"], proof["manifest_hash"], custody.trust, record["manifest"]["authority_trust_hash"]
    )
    receipt_body = _signature(record["receipt"], record["manifest"])
    _subject(record["subject"], custody.trust, record["manifest"], milliseconds(receipt_body["received_at"]))
    if (
        receipt_body["nonce"] != proof["nonce"]
        or receipt_body["sequence"] != proof["witness_sequence"]
        or receipt_body["packet_hash"] != proof["subject_hash"]
        or receipt_body.get("subject_purpose", "closure-packet") != proof["subject_purpose"]
    ):
        raise ClosureError("WITNESS_GATE_RECORD_INVALID")
    page = custody.ledger.audit_export(record["event"]["payload"]["body"]["sequence"], 1)
    if not page["events"] or page["events"][0] != record["event"]:
        raise ClosureError("WITNESS_GATE_RECORD_NOT_ADMITTED")
    return record


def reconcile_witness_operation(custody):
    """Resume only the exact signed pending operation; no new event, timestamp or receipt nonce."""
    config = _config(custody)
    if config is None:
        raise ClosureError("WITNESS_GATE_NOT_CONFIGURED")
    pending = WitnessGate(custody, config)._pending()
    if pending["status"] == "QUARANTINED":
        raise ClosureError("WITNESS_GATE_PENDING_QUARANTINED")
    return custody.append(pending["event"], pending["expected_head"])
