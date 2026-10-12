"""Independent replay of a custody audit export (the CIP network seam).

Given only public material — the operator-pinned enrollment, an audit export (contracts,
signed events, custodian checkpoint) and read access to evidence by digest — rebuild a fresh
ledger with the public ``register``/``append`` APIs, verify the checkpoint (and an earlier
anchor, to detect rollback or a forked history), and replay the transaction's closure packet.
Nothing here signs anything or trusts the exporter's database.
"""

import hmac
import tempfile
from pathlib import Path

from ..contracts import freeze
from ..crypto import verify
from ..ledger import Ledger
from ..protocol import ClosureError, digest
from ..store import EvidenceStore
from ..verdicts import replay_packet


class FetchingStore(EvidenceStore):
    """Local verification store that fetches missing evidence by digest and re-hashes it."""

    def __init__(self, root, fetch):
        super().__init__(root)
        self._fetch = fetch

    def get(self, evidence_hash):
        try:
            return super().get(evidence_hash)
        except ClosureError as exc:
            if exc.code != "EVIDENCE_MISSING":
                raise
        raw = self._fetch(evidence_hash)
        if not isinstance(raw, bytes) or digest(raw) != evidence_hash:
            raise ClosureError("EVIDENCE_HASH_MISMATCH", evidence_hash)
        super().put(raw)
        return raw


def replay_audit_export(
    pages,
    trust,
    expected_trust_hash,
    fetch_evidence,
    *,
    prior_checkpoint=None,
    transaction=None,
    transaction_scope=None,
):
    """Verify an audit export end to end. ``pages`` are consecutive audit-export responses.

    Returns the verified head/sequence, every transaction state and, when ``transaction`` is
    given, the authoritative closure (verdict, reason codes, checks, packet hash) re-derived
    from retained inputs.
    """
    if not hmac.compare_digest(trust.hash, expected_trust_hash):
        raise ClosureError("TRUST_ANCHOR_MISMATCH")
    if not pages:
        raise ClosureError("EXPORT_EMPTY")
    checkpoint = pages[-1]["checkpoint"]
    expected_next = 1
    for page in pages:
        if page.get("version") != "v1" or page.get("trust_hash") != trust.hash:
            raise ClosureError("EXPORT_TRUST_MISMATCH")
        if page["from_sequence"] != expected_next or page["contracts"] != pages[0]["contracts"]:
            raise ClosureError("EXPORT_PAGES_NOT_CONSECUTIVE")
        if page["checkpoint"] != checkpoint and page is not pages[-1]:
            # Earlier pages may carry older checkpoints; they must still be consistent below.
            verify(page["checkpoint"], "checkpoint", trust)
        expected_next = page["from_sequence"] + len(page["events"])
    if pages[-1]["next_sequence"] is not None:
        raise ClosureError("EXPORT_INCOMPLETE")
    with tempfile.TemporaryDirectory(prefix="ace-replay-") as work:
        work = Path(work)
        store = FetchingStore(work / "evidence", fetch_evidence)
        ledger = Ledger(work / "ledger.sqlite", trust, store)
        replay = ledger.import_history if transaction_scope is None else ledger.replay_transaction_history
        kwargs = {} if transaction_scope is None else {"scope": transaction_scope}
        imported = replay(
            [freeze(item["contract"], item["approval"], trust) for item in pages[0]["contracts"]],
            [event for page in pages for event in page["events"]],
            checkpoint,
            prior_checkpoint=prior_checkpoint,
            **kwargs,
        )
        result = {key: imported[key] for key in ("verified_head", "sequence", "transactions")}
        if transaction_scope is not None:
            result["verification_scope"] = {
                "mode": "transaction",
                "transactions": sorted(transaction_scope),
                "global_chain": "SIGNATURES_HASH_LINKS_CHRONOLOGY_CHECKPOINT",
                "foreign_transaction_semantics": "NOT_EVALUATED",
            }
        if transaction is not None:
            packet = imported["packets"].get(transaction)
            if packet is None:
                raise ClosureError("CLOSURE_NOT_ADMITTED", transaction)
            body = replay_packet(packet, store, trust)
            result["closure"] = {
                "protocol": "cip.v1",
                "transaction_id": transaction,
                "verdict": body["verdict"],
                "reason_codes": body["reason_codes"],
                "checks": body["checks"],
                "packet_hash": digest(packet),
                "contract_hash": body["contract_hash"],
                "artifact_hash": body["artifact_hash"],
                "state": result["transactions"][transaction],
            }
        return result
