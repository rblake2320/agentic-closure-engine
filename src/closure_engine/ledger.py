"""Signed event replay, SQLite atomic append and independent checkpoint verification."""

import sqlite3
import sys
from collections import OrderedDict
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path

from .contracts import FrozenContract, freeze
from .crypto import sign, verify
from .protocol import GENESIS, ClosureError, canonical, digest, milliseconds, strict_loads
from .recovery import recovery_status
from .verdicts import replay_packet

_AUTH_SOURCE_EPOCH = digest(
    canonical(
        {
            name: digest(files("closure_engine").joinpath(name).read_bytes())
            for name in ("ledger.py", "contracts.py", "crypto.py", "protocol.py")
        }
    )
)

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
            # The bounded single-writer kernel does not need WAL shared-memory files.
            # Rollback journaling avoids the observed Windows crash/reopen WAL boundary.
            if db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                raise ClosureError("UNSUPPORTED_JOURNAL_MODE")
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
            try:
                db.execute("PRAGMA synchronous=FULL")
                yield db
            finally:
                db.close()
        except sqlite3.Error as exc:
            name = getattr(exc, "sqlite_errorname", "UNKNOWN")
            code = getattr(exc, "sqlite_errorcode", "UNKNOWN")
            raise ClosureError("LEDGER_STORAGE_ERROR", f"{name}/{code}: {exc}") from exc

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
            key = (digest(raw), digest(approval), self.trust.hash, _AUTH_SOURCE_EPOCH)
            cached = getattr(self.store, "authentication_cached", None)
            if cached is None or not cached("contract", key, (raw, approval)):
                freeze(frozen.data, frozen.approval, self.trust)
                remember = getattr(self.store, "remember_authentication", None)
                if remember is not None:
                    remember("contract", key, (raw, approval))
            if frozen.data["transaction_id"] != tx:
                raise ClosureError("CONTRACT_STORAGE_MISMATCH")
            contracts[tx] = frozen
        return contracts

    def _authenticated_row(self, raw):
        """Authenticate physically read canonical bytes; never memoize states or chain position."""
        envelope = strict_loads(raw)
        key = (digest(raw), self.trust.hash, _AUTH_SOURCE_EPOCH)
        cached = getattr(self.store, "authentication_cached", None)
        if cached is None or not cached("event", key, (raw,)):
            verify(envelope, "ledger-event", self.trust)
            if canonical(envelope) != raw:
                raise ClosureError("LEDGER_INTEGRITY_FAILURE")
            remember = getattr(self.store, "remember_authentication", None)
            if remember is not None:
                remember("event", key, (raw,))
        return envelope

    def _fixed_envelope(self, envelope, purpose):
        authenticate = getattr(self.store, "authenticate_envelope", None)
        return (
            verify(envelope, purpose, self.trust)
            if authenticate is None
            else authenticate(envelope, purpose, self.trust, _AUTH_SOURCE_EPOCH)
        )

    def _apply(
        self,
        envelope,
        states,
        packets,
        bindings,
        contracts,
        input_sets,
        *,
        _authenticated=False,
        _parse_context=None,
    ):
        # Only the private physically read/canonical/authenticated row path sets this flag;
        # append/RPC/scoped replays cannot supply a caller-controlled preverified body.
        b = envelope["payload"]["body"] if _authenticated else verify(envelope, "ledger-event", self.trust)
        tx = b["transaction_id"]
        if tx not in contracts or b["contract_hash"] != contracts[tx].hash:
            raise ClosureError("EVENT_CONTRACT_MISMATCH")
        frozen = contracts[tx]
        c = frozen.data if _parse_context is None else _parse_context["contracts"][tx]
        state, old = b["state"], states.get(tx)
        role = self.trust.record(envelope["payload"]["key_id"])["role"]
        if role not in ROLES[state]:
            raise ClosureError("STATE_AUTHORITY_DENIED")
        if state in NORMAL and old != NORMAL[state]:
            raise ClosureError("ILLEGAL_TRANSITION")
        if state in VERDICTS or state == "OBSERVING":
            if b["packet"] is None:
                raise ClosureError("CLOSURE_PACKET_REQUIRED")
            p = replay_packet(b["packet"], self.store, self.trust)
            if tx in bindings and p["binding_hash"] != digest(bindings[tx]):
                raise ClosureError("VERDICT_ARTIFACT_BINDING_MISMATCH")
            raw_inputs = self.store.get(p["inputs_hash"])
            if digest(raw_inputs) != p["inputs_hash"]:
                raise ClosureError("EVIDENCE_HASH_MISMATCH")
            memo = None if _parse_context is None else _parse_context["inputs"].get(p["inputs_hash"])
            if memo is not None and memo[0] == raw_inputs:
                current = memo[1]
            else:
                manifest = strict_loads(raw_inputs)
                current = frozenset(digest(value) for value in manifest["records"] + manifest["receipts"])
                parse_weight = (
                    sys.getsizeof(raw_inputs)
                    + sys.getsizeof(current)
                    + sum(sys.getsizeof(value) for value in current)
                    + 256
                )
                if _parse_context is not None and parse_weight <= 8 * 1024 * 1024:
                    # Ephemeral parse/digest facts only, scoped to THIS full replay. Fresh
                    # physical custody read and SHA verification above are never skipped.
                    while _parse_context["inputs"] and (
                        len(_parse_context["inputs"]) >= 128
                        or _parse_context["bytes"] + parse_weight > 8 * 1024 * 1024
                    ):
                        _, old_inputs = _parse_context["inputs"].popitem(last=False)
                        _parse_context["bytes"] -= old_inputs[2]
                    _parse_context["inputs"][p["inputs_hash"]] = (raw_inputs, current, parse_weight)
                    _parse_context["bytes"] += parse_weight
            prior = input_sets.get(tx, {"records": set(), "evaluated_at": -1})
            if not prior["records"] <= current:
                raise ClosureError("LEDGERED_EVIDENCE_OMITTED")
            evaluated_at = milliseconds(p["evaluated_at"])
            if evaluated_at < prior["evaluated_at"]:
                raise ClosureError("EVALUATION_TIME_REGRESSION")
            input_sets[tx] = {"records": current, "evaluated_at": evaluated_at}
        if state in VERDICTS:
            if old not in ACTIVE or tx in packets:
                raise ClosureError("VERDICT_ALREADY_FINAL_OR_ILLEGAL")
            packet = b["packet"]
            if packet is None:
                raise ClosureError("CLOSURE_PACKET_REQUIRED")
            # The common packet boundary above already reconstructed this body.
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
            binding = self._fixed_envelope(b["binding"], "run-binding")
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
            receipt = self._fixed_envelope(b["receipt"], "action-receipt")
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
            # Reuse the common-boundary replay; no evaluator inputs changed.
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
                store=self.store,
            )
            if status["state"] != state:
                raise ClosureError("RECOVERY_NOT_VERIFIED", status["reason"])
        for ref in b["refs"]:
            self.store.get(ref)
        states[tx] = state

    def _verify(self, db, checkpoint=None, additional_checkpoints=()):
        stored_trust = db.execute("SELECT value FROM meta WHERE key='trust_hash'").fetchone()
        if stored_trust is None or stored_trust[0] != self.trust.hash:
            raise ClosureError("LEDGER_TRUST_MISMATCH")
        checkpoint = checkpoint if checkpoint is not None else self.anchor
        contracts = self._contracts(db)
        cursor = db.execute("SELECT sequence,event_id,envelope,event_hash FROM events ORDER BY sequence")
        try:
            rows = cursor.fetchall()
        finally:
            # A failed replay traceback must not retain a live cursor and mask its typed
            # integrity error with Windows WinError 32 during verification-directory cleanup.
            cursor.close()
        return self._replay_rows(rows, contracts, checkpoint, additional_checkpoints)

    def _replay_rows(self, rows, contracts, checkpoint, additional_checkpoints=(), *, scope=None):
        """Shared signature/chain/time checks; scoped proofs evaluate only their declared subjects.

        Foreign event envelopes still authenticate the global chain. Their artifact/evidence
        semantics are deliberately not evaluated or represented as verified transaction states.
        """
        states, packets, bindings, history, input_sets = {}, {}, {}, {}, {}
        parse_context = {
            "contracts": {tx: value.data for tx, value in contracts.items()},
            "inputs": OrderedDict(),
            "bytes": 0,
        }
        head, seq, last_event_time = GENESIS, 0, None
        seen_event_ids = set()
        for row_seq, event_id, raw, stored_hash in rows:
            envelope = self._authenticated_row(raw)
            b = envelope["payload"]["body"]
            event_time = milliseconds(envelope["payload"]["created_at"])
            if last_event_time is not None and event_time < last_event_time:
                raise ClosureError("EVENT_TIME_REGRESSION")
            if (
                row_seq != seq + 1
                or b["sequence"] != row_seq
                or b["previous_hash"] != head
                or b["event_id"] != event_id
                or digest(raw) != stored_hash
                or event_id in seen_event_ids
            ):
                raise ClosureError("LEDGER_INTEGRITY_FAILURE")
            seen_event_ids.add(event_id)
            if scope is None or b["transaction_id"] in scope:
                self._apply(
                    envelope,
                    states,
                    packets,
                    bindings,
                    contracts,
                    input_sets,
                    _authenticated=True,
                    _parse_context=parse_context,
                )
            elif self.trust.record(envelope["payload"]["key_id"])["role"] not in ROLES[b["state"]]:
                raise ClosureError("STATE_AUTHORITY_DENIED")
            head, seq = stored_hash, row_seq
            last_event_time = event_time
            history[seq] = head
        for anchor in (*additional_checkpoints, *((checkpoint,) if checkpoint is not None else ())):
            cp = verify(anchor, "checkpoint", self.trust)
            checkpoint_head = GENESIS if cp["sequence"] == 0 else history.get(cp["sequence"])
            if cp["trust_hash"] != self.trust.hash or checkpoint_head != cp["head_hash"]:
                raise ClosureError("CHECKPOINT_MISMATCH_OR_TRUNCATION")
        return head, seq, states, packets, bindings, contracts, input_sets, last_event_time

    def replay_transaction_history(self, contracts, events, checkpoint, scope, *, prior_checkpoint=None):
        """Read-only scoped replay with authentic global membership and unchanged own obligations.

        Every event signature/hash link and checkpoint is checked. `_apply` reconstructs all
        declared transactions using their exact retained bytes, including OBSERVING-to-terminal
        input completeness and recovery. Foreign outcome semantics are NOT_EVALUATED.
        """
        scoped_contracts = {}
        for item in contracts:
            frozen = freeze(item.data, item.approval, self.trust)
            transaction = frozen.data["transaction_id"]
            if transaction in scoped_contracts:
                raise ClosureError("CONTRACT_ALREADY_REGISTERED")
            scoped_contracts[transaction] = frozen
        if not scope or set(scoped_contracts) != set(scope):
            raise ClosureError("EXPORT_SCOPE_MISMATCH")
        rows = [
            (
                event["payload"]["body"]["sequence"],
                event["payload"]["body"]["event_id"],
                canonical(event),
                digest(event),
            )
            for event in events
        ]
        result = self._replay_rows(
            rows,
            scoped_contracts,
            checkpoint,
            () if prior_checkpoint is None else (prior_checkpoint,),
            scope=set(scope),
        )
        anchor = verify(checkpoint, "checkpoint", self.trust)
        if anchor["sequence"] != result[1] or anchor["head_hash"] != result[0]:
            raise ClosureError("CHECKPOINT_DOES_NOT_MATCH_EXPORT")
        return {
            "verified_head": result[0],
            "sequence": result[1],
            "transactions": dict(result[2]),
            "packets": dict(result[3]),
        }

    def import_history(self, contracts, events, checkpoint, *, prior_checkpoint=None):
        """Atomically reconstruct an EMPTY verifier ledger and validate its entire history once.

        The same replay path used by append checks signatures, chronology, every transition,
        packet input completeness, and deterministic verdicts. No history is committed until
        both the exact terminal checkpoint and any prior external anchor have passed.
        This verifier-only bulk operation is not exposed by custody or actor services.
        """
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if (
                db.execute("SELECT 1 FROM events LIMIT 1").fetchone()
                or db.execute("SELECT 1 FROM contracts LIMIT 1").fetchone()
            ):
                raise ClosureError("IMPORT_TARGET_NOT_EMPTY")
            for contract in contracts:
                frozen = freeze(contract.data, contract.approval, self.trust)
                db.execute(
                    "INSERT INTO contracts VALUES (?,?,?)",
                    (
                        frozen.data["transaction_id"],
                        frozen.raw,
                        frozen.approval_raw,
                    ),
                )
            for envelope in events:
                body = verify(envelope, "ledger-event", self.trust)
                db.execute(
                    "INSERT INTO events VALUES (?,?,?,?)",
                    (
                        body["sequence"],
                        body["event_id"],
                        canonical(envelope),
                        digest(envelope),
                    ),
                )
            result = self._verify(db, checkpoint, () if prior_checkpoint is None else (prior_checkpoint,))
            anchor = verify(checkpoint, "checkpoint", self.trust)
            if anchor["sequence"] != result[1] or anchor["head_hash"] != result[0]:
                raise ClosureError("CHECKPOINT_DOES_NOT_MATCH_EXPORT")
            db.execute("COMMIT")
        self.anchor = checkpoint
        return {
            "verified_head": result[0],
            "sequence": result[1],
            "transactions": dict(result[2]),
            "packets": dict(result[3]),
        }

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

    @property
    def position(self):
        """Read a verified head/sequence pair in one storage snapshot."""
        with self._db() as db:
            result = self._verify(db)
            return result[0], result[1]

    @property
    def last_event_time(self):
        with self._db() as db:
            return self._verify(db)[7]

    def audit_export(self, from_sequence=1, limit=1000):
        """Registered contracts and a bounded page of signed events from one verified snapshot.

        Everything returned is public, signed material; an independent party rebuilds the
        ledger with ``register`` and ``append`` and checks a custodian checkpoint against it.
        """
        if (
            type(from_sequence) is not int
            or from_sequence < 1
            or type(limit) is not int
            or not 1 <= limit <= 5000
        ):
            raise ClosureError("INVALID_EXPORT_RANGE")
        with self._db() as db:
            head, sequence = self._verify(db)[:2]
            contracts = [
                {"contract": strict_loads(raw), "approval": strict_loads(approval)}
                for raw, approval in db.execute(
                    "SELECT contract,approval FROM contracts ORDER BY transaction_id"
                )
            ]
            events = [
                strict_loads(raw)
                for (raw,) in db.execute(
                    "SELECT envelope FROM events WHERE sequence>=? ORDER BY sequence LIMIT ?",
                    (from_sequence, limit),
                )
            ]
        last = from_sequence + len(events) - 1
        return {
            "head": head,
            "sequence": sequence,
            "contracts": contracts,
            "events": events,
            "next_sequence": last + 1 if last < sequence else None,
        }

    def snapshot(self):
        """Head, sequence, every state and every technical packet from one verified read."""
        with self._db() as db:
            head, sequence, states, packets = self._verify(db)[:4]
        return {"head": head, "sequence": sequence, "transactions": dict(states), "packets": dict(packets)}

    def technical_packets(self):
        """Every admitted technical packet keyed by transaction, from one verified snapshot."""
        with self._db() as db:
            return dict(self._verify(db)[3])

    def summary(self, checkpoint=None):
        """Verified head, sequence and every transaction state from one storage snapshot."""
        with self._db() as db:
            result = self._verify(db, checkpoint)
        return {"verified_head": result[0], "sequence": result[1], "transactions": dict(result[2])}

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
            head, seq, states, packets, bindings, contracts, input_sets, last_event_time = self._verify(db)
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
            if (
                last_event_time is not None
                and milliseconds(envelope["payload"]["created_at"]) < last_event_time
            ):
                raise ClosureError("EVENT_TIME_REGRESSION")
            self._apply(envelope, states, packets, bindings, contracts, input_sets)
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
