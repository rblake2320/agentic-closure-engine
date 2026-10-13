"""Separately enrolled reception witness. Run with ``python -m closure_engine.time_witness``.

This sidecar attests receipt of authenticated closure bytes, not their semantic correctness
or truthful UTC. Pin its manifest independently and retain consumer checkpoints off-host.
"""

import argparse
import hashlib
import json
import re
import secrets
import sqlite3
import ssl
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import TrustStore, verify
from .protocol import ClosureError, canonical, digest, milliseconds, strict_loads, timestamp
from .runtime.files import create_exclusive, create_json
from .runtime.files import read_json as _read_json
from .runtime.identities import init_identity, load_identity
from .runtime.rpc import ServiceClient, ServiceHandler, ServiceServer

DOMAIN = b"ACE/time-witness/v1\x00"
GENESIS = digest(b"ACE/time-witness/v1/genesis")
NONCE = re.compile(r"^[0-9a-f]{64}$")
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
VERDICTS = {"PROVEN", "DISPROVEN", "PARTIALLY_PROVEN", "INDETERMINATE"}


def read_json(path, missing_code="WITNESS_INPUT_MISSING"):
    return _read_json(path, missing_code)


def _now_ms():
    return time.time_ns() // 1_000_000


def _positive(value, maximum=86_400_000):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ClosureError("WITNESS_POLICY_INVALID")
    return value


def _manifest(value):
    fields = {
        "version",
        "purpose",
        "issuer",
        "key_id",
        "public_key",
        "authority_trust_hash",
        "max_packet_age_ms",
        "max_receipt_age_ms",
        "future_tolerance_ms",
        "clock_step_tolerance_ms",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or (value["version"] != "v1" or value["purpose"] != "closure-reception-witness")
    ):
        raise ClosureError("WITNESS_MANIFEST_INVALID")
    if not isinstance(value["issuer"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", value["issuer"]):
        raise ClosureError("WITNESS_MANIFEST_INVALID")
    if value["key_id"] != value["issuer"] + "-key-v1":
        raise ClosureError("WITNESS_MANIFEST_INVALID")
    if not isinstance(value["public_key"], str) or not NONCE.fullmatch(value["public_key"]):
        raise ClosureError("WITNESS_MANIFEST_INVALID")
    if not isinstance(value["authority_trust_hash"], str) or not HASH.fullmatch(
        value["authority_trust_hash"]
    ):
        raise ClosureError("WITNESS_MANIFEST_INVALID")
    for field in (
        "max_packet_age_ms",
        "max_receipt_age_ms",
        "future_tolerance_ms",
        "clock_step_tolerance_ms",
    ):
        _positive(value[field])
    return value


def _trust(value, expected_hash):
    trust = TrustStore.from_dict(value)
    if trust.hash != expected_hash:
        raise ClosureError("WITNESS_AUTHORITY_PIN_MISMATCH")
    return trust


def _enrollment(manifest, expected_pin, trust, expected_authority_pin):
    _manifest(manifest)
    if digest(manifest) != expected_pin:
        raise ClosureError("WITNESS_PIN_MISMATCH")
    if trust.hash != expected_authority_pin or manifest["authority_trust_hash"] != expected_authority_pin:
        raise ClosureError("WITNESS_AUTHORITY_PIN_MISMATCH")
    if any(
        k["public_key"] == manifest["public_key"] or k["issuer"] == manifest["issuer"]
        for k in trust.data["keys"]
    ):
        raise ClosureError("WITNESS_IDENTITY_NOT_SEPARATE")


def initialize(
    root,
    issuer,
    trust,
    expected_authority_pin,
    *,
    max_packet_age_ms=60_000,
    max_receipt_age_ms=60_000,
    future_tolerance_ms=2_000,
    clock_step_tolerance_ms=2_000,
):
    """Operator-only enrollment. Creates persistent private state exclusively, never replaces it."""
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        raise ClosureError("WITNESS_STATE_ALREADY_EXISTS")
    if trust.hash != expected_authority_pin:
        raise ClosureError("WITNESS_AUTHORITY_PIN_MISMATCH")
    for value in (max_packet_age_ms, max_receipt_age_ms, future_tolerance_ms, clock_step_tolerance_ms):
        _positive(value)
    if not isinstance(issuer, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", issuer):
        raise ClosureError("WITNESS_MANIFEST_INVALID")
    if issuer in {key["issuer"] for key in trust.data["keys"]}:
        raise ClosureError("WITNESS_IDENTITY_NOT_SEPARATE")
    public = init_identity(root / "signer", "custodian", issuer)
    manifest = _manifest(
        {
            "version": "v1",
            "purpose": "closure-reception-witness",
            "issuer": issuer,
            "key_id": public["key_id"],
            "public_key": public["public_key"],
            "authority_trust_hash": expected_authority_pin,
            "max_packet_age_ms": max_packet_age_ms,
            "max_receipt_age_ms": max_receipt_age_ms,
            "future_tolerance_ms": future_tolerance_ms,
            "clock_step_tolerance_ms": clock_step_tolerance_ms,
        }
    )
    token = secrets.token_hex(32)
    create_exclusive(root / "client.token", token.encode(), private=True)
    create_json(root / "authority-trust.json", trust.data)
    create_json(root / "manifest.json", manifest)
    create_exclusive(root / "witness.sqlite", b"", private=True)
    with _connect(root / "witness.sqlite") as db:
        db.execute(
            "CREATE TABLE receipts (sequence INTEGER PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, "
            "envelope BLOB NOT NULL)"
        )
    # Written last. Partial enrollment is refused; an existing DB is never silently reconstructed.
    create_json(
        root / "initialized.json",
        {"manifest_hash": digest(manifest), "token_hash": hashlib.sha256(token.encode()).hexdigest()},
    )
    return {
        "manifest": manifest,
        "expected_witness_hash": digest(manifest),
        "token_file": str(root / "client.token"),
    }


@contextmanager
def _connect(path):
    db = None
    try:
        db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=rw", uri=True, timeout=15)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        with db:
            yield db
    except sqlite3.Error as exc:
        raise ClosureError("WITNESS_STORAGE_UNAVAILABLE") from exc
    finally:
        if db is not None:
            db.close()


def _signature(receipt, manifest):
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"algorithm", "body", "signature"}
        or (receipt["algorithm"] != "Ed25519" or not isinstance(receipt["body"], dict))
    ):
        raise ClosureError("WITNESS_RECEIPT_INVALID")
    body = receipt["body"]
    fields = {
        "version",
        "purpose",
        "manifest_hash",
        "issuer",
        "key_id",
        "authority_trust_hash",
        "packet_hash",
        "transaction_id",
        "contract_hash",
        "evaluated_at",
        "received_at",
        "nonce",
        "sequence",
        "previous_hash",
    }
    if set(body) != fields or body["version"] != "v1" or body["purpose"] != "closure-reception":
        raise ClosureError("WITNESS_RECEIPT_INVALID")
    if (
        body["manifest_hash"] != digest(manifest)
        or body["issuer"] != manifest["issuer"]
        or body["key_id"] != manifest["key_id"]
        or body["authority_trust_hash"] != manifest["authority_trust_hash"]
    ):
        raise ClosureError("WITNESS_IDENTITY_MISMATCH")
    if (
        type(body["sequence"]) is not int
        or not 1 <= body["sequence"] < 2**53
        or (not isinstance(body["nonce"], str) or not NONCE.fullmatch(body["nonce"]))
    ):
        raise ClosureError("WITNESS_RECEIPT_INVALID")
    for field in ("packet_hash", "contract_hash", "previous_hash"):
        if not isinstance(body[field], str) or not HASH.fullmatch(body[field]):
            raise ClosureError("WITNESS_RECEIPT_INVALID")
    if not isinstance(body["transaction_id"], str) or not 1 <= len(body["transaction_id"]) <= 150:
        raise ClosureError("WITNESS_RECEIPT_INVALID")
    milliseconds(body["evaluated_at"])
    milliseconds(body["received_at"])
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["public_key"])).verify(
            bytes.fromhex(receipt["signature"]), DOMAIN + canonical(body)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ClosureError("WITNESS_SIGNATURE_INVALID") from exc
    return body


def _packet(packet, trust, manifest, at):
    body = verify(packet, "closure-packet", trust)
    if body["verdict"] not in VERDICTS:
        raise ClosureError("WITNESS_PACKET_NOT_TERMINAL")
    future = manifest["future_tolerance_ms"]
    for value in (body["evaluated_at"], packet["payload"]["created_at"], body["window_end"]):
        if value is not None and milliseconds(value) > at + future:
            raise ClosureError("WITNESS_PACKET_FUTURE")
    if at - milliseconds(body["evaluated_at"]) > manifest["max_packet_age_ms"]:
        raise ClosureError("WITNESS_PACKET_LATE")
    return body


class Witness:
    """Protected local signing service. UTC is the witness host's clock, never a request field."""

    def __init__(self, root, expected_witness_hash, expected_authority_hash, *, expected_checkpoint=None):
        self.root = Path(root)
        self.manifest = read_json(self.root / "manifest.json", "WITNESS_STATE_MISSING")
        self.trust = _trust(
            read_json(self.root / "authority-trust.json", "WITNESS_STATE_MISSING"), expected_authority_hash
        )
        _enrollment(self.manifest, expected_witness_hash, self.trust, expected_authority_hash)
        self.marker = read_json(self.root / "initialized.json", "WITNESS_ENROLLMENT_INCOMPLETE")
        if self.marker.get("manifest_hash") != expected_witness_hash:
            raise ClosureError("WITNESS_PIN_MISMATCH")
        self.key = load_identity(self.root / "signer", "custodian")
        if self.key.private_key.public_key().public_bytes_raw().hex() != self.manifest["public_key"]:
            raise ClosureError("WITNESS_IDENTITY_MISMATCH")
        self.db_path = self.root / "witness.sqlite"
        self.expected_checkpoint = expected_checkpoint
        self._clock = (_now_ms(), time.monotonic_ns())
        self.checkpoint()  # replay before accepting any network request

    def _replay(self, db):
        sequence, head, at = 0, GENESIS, None
        checkpoint_matched = self.expected_checkpoint is None
        cp = self.expected_checkpoint
        if cp is not None:
            if (
                not isinstance(cp, dict)
                or set(cp) != {"manifest_hash", "sequence", "head_hash"}
                or (
                    cp["manifest_hash"] != digest(self.manifest)
                    or type(cp["sequence"]) is not int
                    or cp["sequence"] < 0
                )
            ):
                raise ClosureError("WITNESS_CHECKPOINT_INVALID")
            checkpoint_matched = cp["sequence"] == 0 and cp["head_hash"] == GENESIS
        try:
            rows = db.execute("SELECT sequence,nonce,envelope FROM receipts ORDER BY sequence")
            for row_sequence, nonce, raw in rows:
                receipt = strict_loads(raw)
                body = _signature(receipt, self.manifest)
                received = milliseconds(body["received_at"])
                if (
                    row_sequence != sequence + 1
                    or body["sequence"] != row_sequence
                    or body["nonce"] != nonce
                    or body["previous_hash"] != head
                    or (at is not None and received < at)
                ):
                    raise ClosureError("WITNESS_HISTORY_INVALID")
                sequence, head, at = row_sequence, digest(receipt), received
                if cp is not None and cp["sequence"] == sequence and cp["head_hash"] == head:
                    checkpoint_matched = True
        except sqlite3.Error as exc:
            raise ClosureError("WITNESS_STORAGE_INVALID") from exc
        if not checkpoint_matched:
            raise ClosureError("WITNESS_CHECKPOINT_MISMATCH")
        return sequence, head, at

    def checkpoint(self):
        with _connect(self.db_path) as db:
            sequence, head, _ = self._replay(db)
            return {"manifest_hash": digest(self.manifest), "sequence": sequence, "head_hash": head}

    def receive(self, packet, nonce):
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise ClosureError("WITNESS_NONCE_INVALID")
        with _connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            sequence, head, previous_at = self._replay(db)
            at, monotonic = _now_ms(), time.monotonic_ns()
            elapsed = (monotonic - self._clock[1]) // 1_000_000
            if abs(at - self._clock[0] - elapsed) > self.manifest["clock_step_tolerance_ms"]:
                raise ClosureError("WITNESS_CLOCK_DISCONTINUITY")
            if previous_at is not None and at < previous_at:
                raise ClosureError("WITNESS_CLOCK_REGRESSION")
            packet_body = _packet(packet, self.trust, self.manifest, at)
            old = db.execute("SELECT envelope FROM receipts WHERE nonce=?", (nonce,)).fetchone()
            if old:
                receipt = strict_loads(old[0])
                if receipt["body"]["packet_hash"] != digest(packet):
                    raise ClosureError("WITNESS_NONCE_REUSED")
                return receipt  # exact retry: no new receipt or sequence; consumers still reject reuse
            body = {
                "version": "v1",
                "purpose": "closure-reception",
                "manifest_hash": digest(self.manifest),
                "issuer": self.manifest["issuer"],
                "key_id": self.manifest["key_id"],
                "authority_trust_hash": self.trust.hash,
                "packet_hash": digest(packet),
                "transaction_id": packet_body["transaction_id"],
                "contract_hash": packet_body["contract_hash"],
                "evaluated_at": packet_body["evaluated_at"],
                "received_at": timestamp(at),
                "nonce": nonce,
                "sequence": sequence + 1,
                "previous_hash": head,
            }
            receipt = {
                "algorithm": "Ed25519",
                "body": body,
                "signature": self.key.private_key.sign(DOMAIN + canonical(body)).hex(),
            }
            db.execute("INSERT INTO receipts VALUES (?,?,?)", (sequence + 1, nonce, canonical(receipt)))
            return receipt  # context manager commits synchronously before returning to caller


def verify_receipt(
    receipt,
    packet,
    manifest,
    *,
    expected_witness_hash,
    authority_trust,
    expected_authority_hash,
    expected_nonce,
):
    """Verify bindings and freshness with consumer system UTC; consume separately for replay denial."""
    _enrollment(manifest, expected_witness_hash, authority_trust, expected_authority_hash)
    body = _signature(receipt, manifest)
    if body["nonce"] != expected_nonce:
        raise ClosureError("WITNESS_NONCE_MISMATCH")
    observed = milliseconds(body["received_at"])
    now = _now_ms()
    if observed > now + manifest["future_tolerance_ms"]:
        raise ClosureError("WITNESS_RECEIPT_FUTURE")
    if now - observed > manifest["max_receipt_age_ms"]:
        raise ClosureError("WITNESS_RECEIPT_STALE")
    packet_body = _packet(packet, authority_trust, manifest, observed)
    if (
        digest(packet) != body["packet_hash"]
        or packet_body["transaction_id"] != body["transaction_id"]
        or packet_body["contract_hash"] != body["contract_hash"]
        or packet_body["evaluated_at"] != body["evaluated_at"]
    ):
        raise ClosureError("WITNESS_PACKET_MISMATCH")
    return body


class ConsumerJournal:
    """Durable anti-replay cursor. Keep outside actor custody; creation is explicit, never inferred."""

    @staticmethod
    def initialize(path):
        create_exclusive(path, b"", private=True)
        with _connect(path) as db:
            db.execute(
                "CREATE TABLE consumed (manifest_hash TEXT, nonce TEXT, sequence INTEGER, "
                "head_hash TEXT, received_at INTEGER, PRIMARY KEY (manifest_hash,nonce), "
                "UNIQUE (manifest_hash, sequence))"
            )

    def __init__(self, path):
        self.path = Path(path)

    def consume(self, receipt, packet, manifest, **verification):
        body = verify_receipt(receipt, packet, manifest, **verification)
        with _connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT sequence,received_at FROM consumed WHERE manifest_hash=? "
                "ORDER BY sequence DESC LIMIT 1",
                (body["manifest_hash"],),
            ).fetchone()
            if previous and (
                body["sequence"] <= previous[0] or milliseconds(body["received_at"]) < previous[1]
            ):
                raise ClosureError("WITNESS_REPLAY_OR_REGRESSION")
            try:
                db.execute(
                    "INSERT INTO consumed VALUES (?,?,?,?,?)",
                    (
                        body["manifest_hash"],
                        body["nonce"],
                        body["sequence"],
                        digest(receipt),
                        milliseconds(body["received_at"]),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ClosureError("WITNESS_REPLAY_OR_REGRESSION") from exc
        return {
            "status": "WITNESSED",
            "packet_hash": body["packet_hash"],
            "received_at": body["received_at"],
            "witness_checkpoint": {
                "manifest_hash": body["manifest_hash"],
                "sequence": body["sequence"],
                "head_hash": digest(receipt),
            },
        }


class _Handler(ServiceHandler):
    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def _dispatch(self):
        if not self.host_ok():
            self.send_json(403, {"error": "HOST_OR_ORIGIN_DENIED"})
            return
        if not self.principal():
            self.send_json(401, {"error": "AUTHENTICATION_REQUIRED"})
            return
        try:
            if self.command == "GET" and self.path == "/checkpoint":
                self.send_json(200, self.server.witness.checkpoint())
            elif self.command == "POST" and self.path == "/receipts":
                request = self.json_body()
                if set(request) != {"packet", "nonce"}:
                    raise ClosureError("WITNESS_REQUEST_INVALID")
                self.send_json(201, self.server.witness.receive(request["packet"], request["nonce"]))
            else:
                self.send_json(404, {"error": "ROUTE_NOT_FOUND"})
        except ClosureError as exc:
            self.send_json(409, {"error": exc.code})
        except (OSError, sqlite3.Error):
            self.send_json(503, {"error": "WITNESS_STORAGE_UNAVAILABLE"})


def make_server(witness, host="127.0.0.1", port=8790, *, hosts=None, certificate=None, tls_key=None):
    if host not in {"127.0.0.1", "localhost"} and not (certificate and tls_key):
        raise ClosureError("WITNESS_TLS_REQUIRED_FOR_NON_LOOPBACK")
    creds = {witness.marker["token_hash"]: {"principal": "witness-client", "roles": ["authority"]}}
    server = ServiceServer((host, port), _Handler, hosts=hosts, credentials=creds, read_timeout=5)
    server.witness = witness
    if certificate or tls_key:
        if not (certificate and tls_key):
            server.server_close()
            raise ClosureError("WITNESS_TLS_CONFIG_INVALID")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def request_receipt(url, token, packet, nonce):
    parts = urlsplit(url)
    if parts.scheme != "https" and parts.hostname not in {"127.0.0.1", "localhost"}:
        raise ClosureError("WITNESS_TLS_REQUIRED_FOR_NON_LOOPBACK")
    return ServiceClient(url, token, timeout=10).call("POST", "/receipts", {"packet": packet, "nonce": nonce})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--root", required=True)
    init.add_argument("--issuer", required=True)
    init.add_argument("--authority-trust", required=True)
    init.add_argument("--expected-authority-hash", required=True)
    for cmd in ("serve", "checkpoint"):
        item = sub.add_parser(cmd)
        item.add_argument("--root", required=True)
        item.add_argument("--expected-witness-hash", required=True)
        item.add_argument("--expected-authority-hash", required=True)
        item.add_argument("--expected-checkpoint")
        if cmd == "serve":
            item.add_argument("--host", default="127.0.0.1")
            item.add_argument("--port", type=int, default=8790)
            item.add_argument("--allowed-host", action="append")
            item.add_argument("--tls-cert")
            item.add_argument("--tls-key")
    receive = sub.add_parser("request")
    receive.add_argument("--url", required=True)
    receive.add_argument("--token-file", required=True)
    receive.add_argument("--packet", required=True)
    receive.add_argument("--nonce", required=True)
    receive.add_argument("--out", required=True)
    journal = sub.add_parser("journal-init")
    journal.add_argument("--journal", required=True)
    consumer = sub.add_parser("verify")
    for arg in (
        "receipt",
        "packet",
        "manifest",
        "expected-witness-hash",
        "authority-trust",
        "expected-authority-hash",
        "nonce",
        "journal",
    ):
        consumer.add_argument("--" + arg, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            trust = _trust(read_json(args.authority_trust), args.expected_authority_hash)
            result = initialize(args.root, args.issuer, trust, args.expected_authority_hash)
        elif args.command in {"serve", "checkpoint"}:
            checkpoint = read_json(args.expected_checkpoint) if args.expected_checkpoint else None
            witness = Witness(
                args.root,
                args.expected_witness_hash,
                args.expected_authority_hash,
                expected_checkpoint=checkpoint,
            )
            if args.command == "checkpoint":
                result = witness.checkpoint()
            else:
                server = make_server(
                    witness,
                    args.host,
                    args.port,
                    hosts=args.allowed_host,
                    certificate=args.tls_cert,
                    tls_key=args.tls_key,
                )
                print(json.dumps({"status": "LISTENING", "port": server.server_address[1]}), flush=True)
                try:
                    server.serve_forever()
                finally:
                    server.server_close()
                return 0
        elif args.command == "request":
            receipt = request_receipt(
                args.url, Path(args.token_file).read_text().strip(), read_json(args.packet), args.nonce
            )
            create_json(args.out, receipt)
            result = {"receipt_file": args.out, "receipt_hash": digest(receipt)}
        elif args.command == "journal-init":
            ConsumerJournal.initialize(args.journal)
            result = {"status": "INITIALIZED"}
        else:
            result = ConsumerJournal(args.journal).consume(
                read_json(args.receipt),
                read_json(args.packet),
                read_json(args.manifest),
                expected_witness_hash=args.expected_witness_hash,
                authority_trust=_trust(read_json(args.authority_trust), args.expected_authority_hash),
                expected_authority_hash=args.expected_authority_hash,
                expected_nonce=args.nonce,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ClosureError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"error": exc.code if isinstance(exc, ClosureError) else "WITNESS_IO_ERROR"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
