"""Signed event replay, SQLite atomic append and independent checkpoint verification."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .contracts import FrozenContract, freeze
from .crypto import sign, verify
from .protocol import GENESIS, ClosureError, canonical, digest, milliseconds, strict_loads
from .recovery import recovery_status

VERDICTS = {"PROVEN", "DISPROVEN", "PARTIALLY_PROVEN", "INDETERMINATE"}
ROLES = {
    "DRAFT": {"actor", "owner"},
    "APPROVED": {"owner"},
    "FROZEN": {"authority"},
    "BASELINED": {"verifier"},
    "EXECUTING": {"broker"},
    "VERIFYING": {"broker"},
    "OBSERVING": {"authority"},
    "ACCEPTED": {"owner"},
    "RISK_ACCEPTED": {"owner"},
    "RECOVERY_REQUIRED": {"owner", "authority"},
    "RECOVERED": {"authority"},
    "RECOVERY_FAILED": {"authority"},
    **{v: {"authority"} for v in VERDICTS},
}
NORMAL = {
    "DRAFT": None,
    "APPROVED": "DRAFT",
    "FROZEN": "APPROVED",
    "BASELINED": "FROZEN",
    "EXECUTING": "BASELINED",
    "VERIFYING": "EXECUTING",
    "OBSERVING": "VERIFYING",
    "ACCEPTED": "PROVEN",
    "RECOVERED": "RECOVERY_REQUIRED",
    "RECOVERY_FAILED": "RECOVERY_REQUIRED",
}
ACTIVE = {"FROZEN", "BASELINED", "EXECUTING", "VERIFYING", "OBSERVING"}


class Ledger:
    def __init__(self, path, trust, store, checkpoint=None):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.trust = trust
        self.store = store
        self.anchor = checkpoint
        if self.path.exists() and checkpoint is None:
            raise ClosureError("CHECKPOINT_REQUIRED_FOR_REOPEN")
        if not self.path.exists():
            self._initialize()
        self.verify(checkpoint)

    def _initialize(self):
        with self._db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS contracts "
                "(transaction_id TEXT PRIMARY KEY, contract BLOB NOT NULL, approval BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS events "
                "(sequence INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, "
                "envelope BLOB NOT NULL, event_hash TEXT NOT NULL)"
            )
            db.execute("INSERT OR IGNORE INTO meta VALUES (?,?)", ("trust_hash", self.trust.hash))
            if db.execute("SELECT value FROM meta WHERE key='trust_hash'").fetchone()[0] != self.trust.hash:
                raise ClosureError("LEDGER_TRUST_MISMATCH")

    @contextmanager
    def _db(self):
        try:
            db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            db.execute("PRAGMA synchronous=FULL")
            try:
                yield db
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise ClosureError("LEDGER_STORAGE_ERROR", str(exc)) from exc

    def register(self, frozen):
        freeze(frozen.data, frozen.approval, self.trust)
        tx = frozen.data["transaction_id"]
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT contract,approval FROM contracts WHERE transaction_id=?", (tx,)
            ).fetchone()
            if row and row != (frozen.raw, frozen.approval_raw):
                raise ClosureError("CONTRACT_ALREADY_REGISTERED")
            db.execute(
                "INSERT OR IGNORE INTO contracts VALUES (?,?,?)", (tx, frozen.raw, frozen.approval_raw)
            )
            db.execute("COMMIT")

    def _contracts(self, db):
        contracts = {}
        for tx, raw, approval in db.execute("SELECT transaction_id,contract,approval FROM contracts"):
            frozen = FrozenContract(raw, approval)
            freeze(frozen.data, frozen.approval, self.trust)
            if frozen.data["transaction_id"] != tx:
                raise ClosureError("CONTRACT_STORAGE_MISMATCH")
            contracts[tx] = frozen
        return contracts

    def _apply(self, envelope, states, packets, bindings, contracts):
        b = verify(envelope, "ledger-event", self.trust)
        tx = b["transaction_id"]
        if tx not in contracts or b["contract_hash"] != contracts[tx].hash:
            raise ClosureError("EVENT_CONTRACT_MISMATCH")
        frozen = contracts[tx]
        c = frozen.data
        state, old = b["state"], states.get(tx)
        role = self.trust.record(envelope["payload"]["key_id"])["role"]
        if role not in ROLES[state]:
            raise ClosureError("STATE_AUTHORITY_DENIED")
        if state in NORMAL and old != NORMAL[state]:
            raise ClosureError("ILLEGAL_TRANSITION")
        if state in VERDICTS:
            if old not in ACTIVE or tx in packets:
                raise ClosureError("VERDICT_ALREADY_FINAL_OR_ILLEGAL")
            packet = b["packet"]
            if packet is None:
                raise ClosureError("CLOSURE_PACKET_REQUIRED")
            p = verify(packet, "closure-packet", self.trust)
            if (
                p["verdict"] != state
                or p["contract_hash"] != frozen.hash
                or p["transaction_id"] != tx
                or p["attempt_id"] != c["attempt_id"]
                or p["target_id"] != c["target_id"]
                or p["ledger_head"] != b["previous_hash"]
            ):
                raise ClosureError("VERDICT_PACKET_MISMATCH")
            fixed_fields = {
                "approval_hash": digest(frozen.approval),
                "baseline_hash": c["baseline_hash"],
                "evaluator_hash": c["evaluator_hash"],
                "policy_hash": c["policy_hash"],
                "trust_hash": self.trust.hash,
                "parent_packet_hash": c["parent_packet_hash"],
            }
            if any(p[k] != value for k, value in fixed_fields.items()):
                raise ClosureError("VERDICT_POLICY_BINDING_MISMATCH")
            if tx in bindings and (
                p["binding_hash"] != digest(bindings[tx])
                or p["artifact_hash"] != bindings[tx]["payload"]["body"]["artifact_hash"]
            ):
                raise ClosureError("VERDICT_ARTIFACT_BINDING_MISMATCH")
            if state == "PROVEN" and old != "OBSERVING":
                raise ClosureError("OBSERVATION_PHASE_REQUIRED")
            if state == "PARTIALLY_PROVEN" and old != "VERIFYING":
                raise ClosureError("ILLEGAL_PARTIAL_TRANSITION")
            if state == "PROVEN" and (
                not p["window_complete"]
                or p["recovery_required"]
                or any(p["checks"].get(ch["id"]) != "PASS" for ch in c["checks"] if ch["mandatory"])
            ):
                raise ClosureError("PROVEN_PACKET_INCOMPLETE")
            packets[tx] = packet
        elif state == "RECOVERY_REQUIRED":
            if old not in VERDICTS or tx not in packets:
                raise ClosureError("ILLEGAL_TRANSITION")
        elif state == "RISK_ACCEPTED":
            if old not in VERDICTS or b["risk"] is None:
                raise ClosureError("ILLEGAL_RISK_ACCEPTANCE")
            risk = verify(b["risk"], "risk-acceptance", self.trust)
            if risk["packet_hash"] != digest(packets[tx]) or risk["contract_hash"] != frozen.hash:
                raise ClosureError("RISK_PACKET_MISMATCH")
            if milliseconds(risk["expires_at"]) <= milliseconds(envelope["payload"]["created_at"]):
                raise ClosureError("RISK_ACCEPTANCE_EXPIRED")
            return
        if state == "BASELINED":
            if len(b["refs"]) != 1:
                raise ClosureError("BASELINE_MANIFEST_REQUIRED")
            baseline = strict_loads(self.store.get(b["refs"][0]))
            if set(baseline) != {"artifact_hash", "protected"} or (
                baseline["artifact_hash"] != c["baseline_hash"]
                or set(baseline["protected"]) != set(c["protected_resources"])
            ):
                raise ClosureError("BASELINE_COVERAGE_MISMATCH")
            self.store.get(c["baseline_hash"])
            for resource_hash in baseline["protected"].values():
                self.store.get(resource_hash)
        if state == "EXECUTING":
            if b["binding"] is None:
                raise ClosureError("RUN_BINDING_REQUIRED")
            binding = verify(b["binding"], "run-binding", self.trust)
            if any(
                binding[k] != v
                for k, v in {
                    "transaction_id": tx,
                    "contract_hash": frozen.hash,
                    "target_id": c["target_id"],
                    "attempt_id": c["attempt_id"],
                }.items()
            ):
                raise ClosureError("RUN_BINDING_MISMATCH")
            bindings[tx] = b["binding"]
        if state == "VERIFYING":
            if b["receipt"] is None:
                raise ClosureError("ACTION_RECEIPT_REQUIRED")
            receipt = verify(b["receipt"], "action-receipt", self.trust)
            binding = bindings[tx]["payload"]["body"]
            if any(
                receipt[k] != binding[k]
                for k in ("contract_hash", "transaction_id", "attempt_id", "artifact_hash", "target_id")
            ):
                raise ClosureError("ACTION_RECEIPT_MISMATCH")
            if receipt["status"] == "UNKNOWN":
                raise ClosureError("UNKNOWN_ACTION_RESULT")
        if state == "OBSERVING":
            if b["packet"] is None:
                raise ClosureError("IMMEDIATE_VERIFICATION_REQUIRED")
            p = verify(b["packet"], "closure-packet", self.trust)
            if p["contract_hash"] != frozen.hash or p["ledger_head"] != b["previous_hash"]:
                raise ClosureError("IMMEDIATE_PACKET_MISMATCH")
            if any(
                p["checks"].get(ch["id"]) != "PASS"
                for ch in c["checks"]
                if ch["mandatory"] and ch["phase"] == "instant"
            ):
                raise ClosureError("IMMEDIATE_CHECKS_FAILED")
        if state in {"RECOVERED", "RECOVERY_FAILED"}:
            if b["packet"] is not None:
                if b["recovery_contract"] is None or b["recovery_approval"] is None:
                    raise ClosureError("RECOVERY_CONTRACT_REQUIRED")
                child = freeze(b["recovery_contract"], b["recovery_approval"], self.trust)
            else:
                child = None
            status = recovery_status(
                packets[tx],
                child,
                b["packet"],
                self.trust,
                milliseconds(envelope["payload"]["created_at"]),
                c["recovery"]["deadline_ms"],
            )
            if status["state"] != state:
                raise ClosureError("RECOVERY_NOT_VERIFIED", status["reason"])
        for ref in b["refs"]:
            self.store.get(ref)
        states[tx] = state

    def _verify(self, db, checkpoint=None):
        stored_trust = db.execute("SELECT value FROM meta WHERE key='trust_hash'").fetchone()
        if stored_trust is None or stored_trust[0] != self.trust.hash:
            raise ClosureError("LEDGER_TRUST_MISMATCH")
        checkpoint = checkpoint if checkpoint is not None else self.anchor
        contracts = self._contracts(db)
        states, packets, bindings, history = {}, {}, {}, {}
        head, seq = GENESIS, 0
        for row_seq, event_id, raw, stored_hash in db.execute(
            "SELECT sequence,event_id,envelope,event_hash FROM events ORDER BY sequence"
        ):
            envelope = strict_loads(raw)
            b = verify(envelope, "ledger-event", self.trust)
            if (
                row_seq != seq + 1
                or b["sequence"] != row_seq
                or b["previous_hash"] != head
                or b["event_id"] != event_id
                or digest(envelope) != stored_hash
                or canonical(envelope) != raw
            ):
                raise ClosureError("LEDGER_INTEGRITY_FAILURE")
            self._apply(envelope, states, packets, bindings, contracts)
            head, seq = stored_hash, row_seq
            history[seq] = head
        if checkpoint is not None:
            cp = verify(checkpoint, "checkpoint", self.trust)
            checkpoint_head = GENESIS if cp["sequence"] == 0 else history.get(cp["sequence"])
            if cp["trust_hash"] != self.trust.hash or checkpoint_head != cp["head_hash"]:
                raise ClosureError("CHECKPOINT_MISMATCH_OR_TRUNCATION")
        return head, seq, states, packets, bindings, contracts

    def verify(self, checkpoint=None):
        with self._db() as db:
            return self._verify(db, checkpoint)[0]

    @property
    def head(self):
        return self.verify()

    @property
    def sequence(self):
        with self._db() as db:
            return self._verify(db)[1]

    def state(self, transaction_id):
        with self._db() as db:
            return self._verify(db)[2].get(transaction_id)

    def technical_packet(self, transaction_id):
        with self._db() as db:
            return self._verify(db)[3].get(transaction_id)

    def append(self, envelope, expected_head):
        verify(envelope, "ledger-event", self.trust)
        b = envelope["payload"]["body"]
        raw = canonical(envelope)
        h = digest(raw)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            head, seq, states, packets, bindings, contracts = self._verify(db)
            existing = db.execute(
                "SELECT envelope,event_hash FROM events WHERE event_id=?", (b["event_id"],)
            ).fetchone()
            if existing:
                if existing[0] != raw:
                    raise ClosureError("EVENT_ID_CONFLICT")
                db.execute("COMMIT")
                return existing[1]
            if head != expected_head or b["previous_hash"] != head or b["sequence"] != seq + 1:
                raise ClosureError("STALE_LEDGER_HEAD")
            self._apply(envelope, states, packets, bindings, contracts)
            db.execute("INSERT INTO events VALUES (?,?,?,?)", (seq + 1, b["event_id"], raw, h))
            db.execute("COMMIT")
        return h

    def checkpoint(self, custodian, created_at):
        with self._db() as db:
            head, seq, *_ = self._verify(db)
        checkpoint = sign(
            custodian,
            "checkpoint",
            {"sequence": seq, "head_hash": head, "trust_hash": self.trust.hash},
            created_at,
        )
        verify(checkpoint, "checkpoint", self.trust)
        return checkpoint
