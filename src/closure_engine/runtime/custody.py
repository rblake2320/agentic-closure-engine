"""Custody: the only writer of the ledger, evidence and transaction records.

Custody holds the custodian key and nothing else. It never trusts callers: every submitted
object must carry the signature of the role that owns it, events are admitted only through
``Ledger.append`` (signature, role-per-state, chronology, packet replay), and derived records
(binding, packets, baseline manifest) are taken from events the ledger has already accepted.
Ingestion receipts carry the custodian's own clock.

Layout under the custodian state root: ledger.sqlite, checkpoint.json, evidence/,
transactions/<slug>.json, records/<slug>/<hash>.json, receipts/<slug>/<hash>.json.
"""

import threading

from ..contracts import freeze
from ..crypto import sign, verify
from ..ledger import Ledger
from ..protocol import POLICY_HASH, ClosureError, digest, strict_loads, validate
from ..store import EvidenceStore
from .clock import SystemClock
from .deployment import slug
from .files import create_json, read_json, replace_json

PACKET_STATES = {"OBSERVING", "PROVEN", "DISPROVEN", "PARTIALLY_PROVEN", "INDETERMINATE"}
VERDICT_STATES = PACKET_STATES - {"OBSERVING"}
META_FIELDS = {
    "transaction_id",
    "target_id",
    "contract",
    "artifact_hash",
    "current_baseline_hash",
    "settle_ms",
}


class LocalCustody:
    def __init__(self, deployment, trust, clock=None):
        self.deployment = deployment
        self.trust = trust
        self.clock = clock or SystemClock()
        self.root = deployment.role_root("custodian")
        self.store = EvidenceStore(self.root / "evidence")
        self._ledger = None
        self._lock = threading.RLock()
        self._cache = None  # (file identity, verified snapshot)

    # ----- ledger --------------------------------------------------------------------------
    @property
    def ledger(self):
        if self._ledger is None:
            path = self.root / "ledger.sqlite"
            checkpoint = (
                read_json(self.root / "checkpoint.json", "CHECKPOINT_MISSING") if path.exists() else None
            )
            self._ledger = Ledger(path, self.trust, self.store, checkpoint=checkpoint)
        return self._ledger

    def _custodian(self):
        return self.deployment.identity("custodian", self.trust)

    def _file_identity(self):
        path = self.root / "ledger.sqlite"
        try:
            stat = path.stat()
        except FileNotFoundError:
            return None
        return (stat.st_mtime_ns, stat.st_size, stat.st_ino)

    def snapshot(self):
        """Verified ledger snapshot, re-verified in full whenever the database file changes.

        Appends always run the ledger's full admission. Reads reuse the last verified snapshot
        only while the file is byte-for-byte unchanged on disk (mtime, size, inode).
        """
        with self._lock:
            before = self._file_identity()
            if self._cache is not None and before is not None and self._cache[0] == before:
                return self._cache[1]
            snapshot = self.ledger.snapshot()
            after = self._file_identity()
            self._cache = (after, snapshot) if before == after and after is not None else None
            return snapshot

    def position(self):
        snapshot = self.snapshot()
        return snapshot["head"], snapshot["sequence"]

    def summary(self):
        snapshot = self.snapshot()
        return {
            "verified_head": snapshot["head"],
            "sequence": snapshot["sequence"],
            "transactions": dict(snapshot["transactions"]),
        }

    def state(self, tx):
        return self.snapshot()["transactions"].get(tx)

    def checkpoint(self):
        with self._lock:
            checkpoint = self.ledger.checkpoint(self._custodian(), self.clock.now())
            replace_json(self.root / "checkpoint.json", checkpoint)
            return checkpoint

    def _sign_checkpoint(self, sequence, head):
        body = {"sequence": sequence, "head_hash": head, "trust_hash": self.trust.hash}
        checkpoint = sign(self._custodian(), "checkpoint", body, self.clock.now())
        replace_json(self.root / "checkpoint.json", checkpoint)
        return checkpoint

    def append(self, event, expected_head):
        """Admit one signed ledger event, then derive records from what the ledger accepted."""
        with self._lock:
            body = verify(event, "ledger-event", self.trust)
            meta = self.tx(body["transaction_id"])
            if body["state"] == "EXECUTING" and (
                meta["pending_binding"] is None or body["binding"] != meta["pending_binding"]
            ):
                raise ClosureError("BINDING_NOT_ISSUED_BY_AUTHORITY")
            event_hash = self.ledger.append(event, expected_head)
            self._cache = None
            if body["state"] == "EXECUTING":
                meta["binding"] = body["binding"]
            if body["state"] == "BASELINED":
                meta["manifest_hash"] = body["refs"][0]
            if body["state"] in PACKET_STATES:
                meta["packets"].append(digest(body["packet"]))
                if body["state"] in VERDICT_STATES:
                    meta["verdict_packet"] = body["packet"]
            self._save(meta)
            # The ledger just verified and admitted this event under our lock: sign its head
            # directly instead of replaying the whole history again.
            self._sign_checkpoint(body["sequence"], event_hash)
            return {"event_hash": event_hash, "head": event_hash, "sequence": body["sequence"]}

    def view(self, tx):
        """One verified ledger snapshot projected for one transaction (state + technical packet)."""
        snapshot = self.snapshot()
        return {
            "verified_head": snapshot["head"],
            "sequence": snapshot["sequence"],
            "state": snapshot["transactions"].get(tx),
            "packet": snapshot["packets"].get(tx),
        }

    def listing(self):
        """Every custody transaction, including staged proposals not yet in the ledger.

        States and verdicts come from one verified ledger snapshot; a proposal that the owner
        has not approved is reported as PROPOSED with approved=False and no verdict.
        """
        snapshot = self.snapshot()
        summary = {k: snapshot[k] for k in ("transactions", "sequence")}
        summary["verified_head"] = snapshot["head"]
        packets = snapshot["packets"]
        items = []
        folder = self.root / "transactions"
        for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
            meta = read_json(path, "TRANSACTION_UNKNOWN")
            tx = meta["transaction_id"]
            packet = packets.get(tx)
            body = packet["payload"]["body"] if packet else None
            items.append(
                {
                    "transaction_id": tx,
                    "target_id": meta["target_id"],
                    "state": summary["transactions"].get(tx, "PROPOSED"),
                    "approved": meta["approval"] is not None,
                    "verdict": body["verdict"] if body else None,
                    "technical_packet_hash": digest(packet) if packet else None,
                    "parent_transaction": meta["parent_transaction"],
                    "child_transaction": meta["child_transaction"],
                }
            )
        return dict(summary, items=items)

    def technical_packet(self, tx):
        """The ledger's authoritative verdict packet for ``tx`` (None until a verdict is admitted)."""
        return self.snapshot()["packets"].get(tx)

    def audit_export(self, from_sequence=1, limit=1000):
        """Public replay seam: contracts, a bounded page of signed events, and a custodian
        checkpoint over the exact head of the same verified snapshot."""
        with self._lock:
            export = self.ledger.audit_export(from_sequence, limit)
            body = {
                "sequence": export["sequence"],
                "head_hash": export["head"],
                "trust_hash": self.trust.hash,
            }
            checkpoint = sign(self._custodian(), "checkpoint", body, self.clock.now())
            return {
                "version": "v1",
                "trust_hash": self.trust.hash,
                "contracts": export["contracts"],
                "events": export["events"],
                "from_sequence": from_sequence,
                "next_sequence": export["next_sequence"],
                "checkpoint": checkpoint,
            }

    # ----- evidence ------------------------------------------------------------------------
    def evidence_get(self, evidence_hash):
        return self.store.get(evidence_hash)

    def evidence_put(self, raw):
        return self.store.put(raw)

    # ----- transactions --------------------------------------------------------------------
    def _path(self, tx):
        return self.root / "transactions" / (slug(tx) + ".json")

    def tx(self, tx):
        meta = read_json(self._path(tx), "TRANSACTION_UNKNOWN")
        if meta.get("transaction_id") != tx:
            raise ClosureError("TRANSACTION_STORAGE_MISMATCH", tx)
        return meta

    def exists(self, tx):
        return self._path(tx).exists()

    def _save(self, meta):
        replace_json(self._path(meta["transaction_id"]), meta)

    def create_tx(self, proposal, parent_transaction=None):
        """Actor proposal: contract draft plus staged artifact and baseline bytes in custody."""
        with self._lock:
            if not isinstance(proposal, dict) or set(proposal) != META_FIELDS:
                raise ClosureError("INVALID_PROPOSAL")
            contract = proposal["contract"]
            validate("closure-contract", contract)
            tx = proposal["transaction_id"]
            if contract["transaction_id"] != tx or contract["target_id"] != proposal["target_id"]:
                raise ClosureError("PROPOSAL_SUBJECT_MISMATCH")
            if contract["trust_hash"] != self.trust.hash or contract["policy_hash"] != POLICY_HASH:
                raise ClosureError("POLICY_OR_TRUST_MISMATCH")
            if digest(self.store.get(proposal["current_baseline_hash"])) != contract["baseline_hash"]:
                raise ClosureError("BASELINE_EVIDENCE_MISSING")
            self.store.get(proposal["artifact_hash"])
            if type(proposal["settle_ms"]) is not int or not 0 <= proposal["settle_ms"] <= 600_000:
                raise ClosureError("INVALID_PROPOSAL")
            if self._path(tx).exists():
                raise ClosureError("TRANSACTION_ALREADY_EXISTS", tx)
            parent = None
            if parent_transaction is None:
                if contract["parent_packet_hash"] is not None:
                    raise ClosureError("RECOVERY_PARENT_REQUIRED")
                if proposal["artifact_hash"] == contract["baseline_hash"]:
                    raise ClosureError("ARTIFACT_ALREADY_ACTIVE")
            else:
                parent = self.tx(parent_transaction)
                packet = parent.get("verdict_packet")
                if self.state(parent_transaction) != "RECOVERY_REQUIRED" or packet is None:
                    raise ClosureError("RECOVERY_NOT_REQUIRED", parent_transaction)
                if parent["child_transaction"] is not None:
                    raise ClosureError("RECOVERY_ALREADY_STARTED", parent["child_transaction"])
                body = packet["payload"]["body"]
                if (
                    contract["parent_packet_hash"] != digest(packet)
                    or contract["baseline_hash"] != body["artifact_hash"]
                    or proposal["artifact_hash"] != parent["contract"]["baseline_hash"]
                    or proposal["target_id"] != parent["target_id"]
                ):
                    raise ClosureError("RECOVERY_PRECONDITION_MISMATCH")
            meta = dict(
                proposal,
                approval=None,
                binding=None,
                pending_binding=None,
                manifest_hash=None,
                packets=[],
                verdict_packet=None,
                parent_transaction=parent_transaction,
                child_transaction=None,
            )
            create_json(self._path(tx), meta)
            if parent is not None:
                parent["child_transaction"] = tx
                self._save(parent)
            return {"transaction_id": tx, "contract_hash": digest(contract), "state": "PROPOSED"}

    def set_approval(self, tx, approval):
        """Owner approval: verified, frozen and registered before any lifecycle event."""
        with self._lock:
            meta = self.tx(tx)
            if meta["approval"] is not None:
                raise ClosureError("ALREADY_APPROVED", tx)
            frozen = freeze(meta["contract"], approval, self.trust)
            meta["approval"] = approval
            self.ledger.register(frozen)
            self._cache = None
            self._save(meta)
            return {"transaction_id": tx, "contract_hash": frozen.hash}

    def set_binding(self, tx, binding):
        """Authority run binding, accepted only when it binds this contract and staged artifact."""
        with self._lock:
            meta = self.tx(tx)
            if meta["binding"] is not None or meta["pending_binding"] is not None:
                raise ClosureError("RUN_ALREADY_BOUND", tx)
            body = verify(binding, "run-binding", self.trust)
            contract = meta["contract"]
            expected = {
                "transaction_id": tx,
                "attempt_id": contract["attempt_id"],
                "contract_hash": digest(contract),
                "artifact_hash": meta["artifact_hash"],
                "target_id": meta["target_id"],
            }
            if any(body[k] != v for k, v in expected.items()):
                raise ClosureError("RUN_BINDING_MISMATCH")
            meta["pending_binding"] = binding
            self._save(meta)
            return {"transaction_id": tx, "binding_hash": digest(binding)}

    def records(self, tx):
        return self._items("records", tx)

    def receipts(self, tx):
        return self._items("receipts", tx)

    def _items(self, kind, tx):
        folder = self.root / kind / slug(tx)
        if not folder.is_dir():
            return []
        items = []
        for path in sorted(folder.glob("*.json")):
            value = read_json(path, "CUSTODY_RECORD_MISSING")
            if digest(value) != path.stem.replace("sha256-", "sha256:"):
                raise ClosureError("CUSTODY_RECORD_TAMPERED", str(path))
            items.append(value)
        return items

    def _keep(self, kind, tx, value):
        path = self.root / kind / slug(tx) / (digest(value).replace(":", "-") + ".json")
        if not path.exists():
            create_json(path, value)
        return digest(value)

    def ingest(self, tx, observation):
        """Verifier observation in; custodian ingestion receipt with custody's own clock out."""
        with self._lock:
            body = verify(observation, "observation", self.trust)
            meta = self.tx(tx)
            if body["transaction_id"] != tx or body["contract_hash"] != digest(meta["contract"]):
                raise ClosureError("OBSERVATION_SUBJECT_MISMATCH")
            now = self.clock.now()
            ingestion = sign(
                self._custodian(),
                "ingestion",
                {"envelope_hash": digest(observation), "received_at": now},
                now,
            )
            record = {"observation": observation, "ingestion": ingestion}
            return {"record_hash": self._keep("records", tx, record), "received_at": now}

    def submit_receipt(self, tx, receipt):
        with self._lock:
            body = verify(receipt, "action-receipt", self.trust)
            meta = self.tx(tx)
            if body["transaction_id"] != tx or body["contract_hash"] != digest(meta["contract"]):
                raise ClosureError("RECEIPT_SUBJECT_MISMATCH")
            return {"receipt_hash": self._keep("receipts", tx, receipt)}

    def manifest(self, tx):
        meta = self.tx(tx)
        if meta["manifest_hash"] is None:
            raise ClosureError("BASELINE_MANIFEST_REQUIRED", tx)
        return strict_loads(self.store.get(meta["manifest_hash"]))
