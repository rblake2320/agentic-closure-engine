"""Public-only historical time-assurance wrapper around unchanged ACE portable v2 proof."""

import argparse
import base64
import sys

from .contracts import freeze
from .crypto import TrustStore
from .protocol import ClosureError, canonical, digest, milliseconds
from .recovery import recovery_status
from .runtime.portable import encode_bundle, export_bundle, read_bundle, verify_bundle
from .runtime.witness_gate import CONSUMPTION_DOMAIN, _verify
from .time_witness import _enrollment, _signature, _subject

VERSION = "ace.time-assurance.v1"
VERDICTS = {"PROVEN", "DISPROVEN", "PARTIALLY_PROVEN", "INDETERMINATE"}


def _events(bundle):
    return [event for page in bundle["portable"]["pages"] for event in page["events"]]


def required_events(bundle, transaction, packet_hash, state):
    """Derive requirements from authenticated history; unsigned wrapper labels never select them."""
    events = _events(bundle)
    terminals = {}
    for event in events:
        body = event["payload"]["body"]
        if body["state"] in VERDICTS and body["packet"] is not None:
            terminals[digest(body["packet"])] = event
    required, pending = {}, [packet_hash]
    if state in {"RECOVERED", "RECOVERY_FAILED", "ACCEPTED"}:
        outcomes = [
            event
            for event in events
            if event["payload"]["body"]["transaction_id"] == transaction
            and event["payload"]["body"]["state"] == state
        ]
        if not outcomes:
            raise ClosureError("TIME_ASSURANCE_UNAVAILABLE")
        final = outcomes[-1]
        required[digest(final)] = final
        child = final["payload"]["body"].get("packet")
        if child is not None:
            pending.append(digest(child))
    while pending:
        reference = pending.pop()
        event = terminals.get(reference)
        if event is None:
            raise ClosureError("TIME_ASSURANCE_UNAVAILABLE")
        event_hash = digest(event)
        if event_hash in required:
            continue
        required[event_hash] = event
        parent = event["payload"]["body"]["packet"]["payload"]["body"]["parent_packet_hash"]
        if parent is not None:
            pending.append(parent)
    scope = set(bundle["portable"]["scope"]["transactions"])
    if any(event["payload"]["body"]["transaction_id"] not in scope for event in required.values()):
        raise ClosureError("TIME_ASSURANCE_SCOPE_MISMATCH")
    return list(sorted(required.values(), key=lambda event: event["payload"]["body"]["sequence"]))


def export_time_assurance(custody, transaction):
    """Package retained public records; external consumers must supply both independent pins."""
    bundle = export_bundle(custody, transaction)
    view = custody.view(transaction)
    packet = view["packet"]
    if packet is None:
        raise ClosureError("TIME_ASSURANCE_UNAVAILABLE")
    required = required_events(bundle, transaction, digest(packet), view["state"])
    try:
        sidecars = [custody.witness_record(digest(event)) for event in required]
    except ClosureError as exc:
        raise ClosureError("TIME_ASSURANCE_UNAVAILABLE") from exc
    wrapper = {
        "version": VERSION,
        "transaction_id": transaction,
        "portable_bundle": bundle,
        "sidecars": sidecars,
    }
    encode_bundle(wrapper)
    return wrapper


class _PublicStore:
    def __init__(self, proof):
        self.evidence = proof["evidence"]

    def get(self, reference):
        if reference not in self.evidence:
            raise ClosureError("EVIDENCE_MISSING")
        raw = base64.b64decode(self.evidence[reference], validate=True)
        if digest(raw) != reference:
            raise ClosureError("EVIDENCE_HASH_MISMATCH")
        return raw


def _sidecar(record, event, trust, witness_pin, authority_pin):
    fields = {"version", "event", "subject", "receipt", "consumption", "manifest", "config_hash"}
    if not isinstance(record, dict) or set(record) != fields or record["version"] != "v1":
        raise ClosureError("TIME_ASSURANCE_RECORD_INVALID")
    if canonical(record["event"]) != canonical(event):
        raise ClosureError("TIME_ASSURANCE_EVENT_MISMATCH")
    _enrollment(record["manifest"], witness_pin, trust, authority_pin)
    proof = _verify(record["consumption"], CONSUMPTION_DOMAIN, trust)
    expected_fields = {
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
    if not isinstance(proof, dict) or set(proof) != expected_fields:
        raise ClosureError("TIME_ASSURANCE_CONSUMPTION_INVALID")
    receipt = _signature(record["receipt"], record["manifest"])
    subject = _subject(record["subject"], trust, record["manifest"], milliseconds(receipt["received_at"]))
    expected = {
        "manifest_hash": witness_pin,
        "nonce": receipt["nonce"],
        "witness_sequence": receipt["sequence"],
        "receipt_hash": digest(record["receipt"]),
        "subject_hash": digest(record["subject"]),
        "subject_purpose": receipt.get("subject_purpose", "closure-packet"),
        "event_hash": digest(event),
        "expected_head": event["payload"]["body"]["previous_hash"],
        "config_hash": record["config_hash"],
    }
    if any(proof[field] != value for field, value in expected.items()) or (
        receipt["packet_hash"] != expected["subject_hash"]
        or subject["transaction_id"] != receipt["transaction_id"]
        or subject["contract_hash"] != receipt["contract_hash"]
        or subject["evaluated_at"] != receipt["evaluated_at"]
    ):
        raise ClosureError("TIME_ASSURANCE_BINDING_MISMATCH")
    if type(proof["consumption_index"]) is not int or proof["consumption_index"] < 1:
        raise ClosureError("TIME_ASSURANCE_CONSUMPTION_INVALID")
    delta = milliseconds(proof["consumed_at"]) - milliseconds(receipt["received_at"])
    if delta < -record["manifest"]["future_tolerance_ms"] or delta > record["manifest"]["max_receipt_age_ms"]:
        raise ClosureError("TIME_ASSURANCE_HISTORICAL_FRESHNESS_INVALID")
    body = event["payload"]["body"]
    if body["state"] == "ACCEPTED":
        if (
            proof["subject_purpose"] != "closure-packet"
            or receipt["transaction_id"] != body["transaction_id"]
        ):
            raise ClosureError("TIME_ASSURANCE_SUBJECT_PURPOSE_MISMATCH")
    elif proof["subject_purpose"] != "ledger-event" or record["subject"] != event:
        raise ClosureError("TIME_ASSURANCE_SUBJECT_PURPOSE_MISMATCH")
    return proof, receipt


def verify_time_assurance(
    wrapper,
    *,
    expected_authority_hash,
    expected_witness_hash,
    expected_transaction,
    expected_contract_hash,
    expected_artifact_hash,
    prior_checkpoint=None,
):
    """Historical public replay. Every pin and subject binding is mandatory and independently supplied."""
    if not isinstance(wrapper, dict) or set(wrapper) != {
        "version",
        "transaction_id",
        "portable_bundle",
        "sidecars",
    }:
        raise ClosureError("TIME_ASSURANCE_INVALID")
    if wrapper["version"] != VERSION or wrapper["transaction_id"] != expected_transaction:
        raise ClosureError("TIME_ASSURANCE_SUBJECT_MISMATCH")
    if not all(
        isinstance(value, str) and value
        for value in (
            expected_authority_hash,
            expected_witness_hash,
            expected_transaction,
            expected_contract_hash,
            expected_artifact_hash,
        )
    ):
        raise ClosureError("TIME_ASSURANCE_EXPECTED_BINDINGS_REQUIRED")
    bundle = wrapper["portable_bundle"]
    native = verify_bundle(
        bundle,
        expected_authority_hash,
        prior_checkpoint=prior_checkpoint,
        expected_transaction=expected_transaction,
        expected_contract_hash=expected_contract_hash,
        expected_artifact_hash=expected_artifact_hash,
    )
    trust = TrustStore.from_dict(bundle["portable"]["trust"])
    closure = native["closure"]
    required = required_events(bundle, expected_transaction, closure["packet_hash"], closure["state"])
    if not isinstance(wrapper["sidecars"], list) or len(wrapper["sidecars"]) != len(required):
        raise ClosureError("TIME_ASSURANCE_REQUIRED_RECEIPT_MISSING")
    supplied = {}
    for record in wrapper["sidecars"]:
        if not isinstance(record, dict) or "event" not in record:
            raise ClosureError("TIME_ASSURANCE_RECORD_INVALID")
        event_hash = digest(record["event"])
        if event_hash in supplied:
            raise ClosureError("TIME_ASSURANCE_REPLAYED_RECEIPT")
        supplied[event_hash] = record
    if set(supplied) != {digest(event) for event in required}:
        raise ClosureError("TIME_ASSURANCE_SCOPE_MISMATCH")
    store = _PublicStore(bundle["portable"])
    nonce_set, sequence_set, consumption_set, summaries = set(), set(), set(), []
    last_sequence, last_consumption, last_received = 0, 0, None
    packets = {}
    required_by_hash = {digest(event): event for event in required}
    for event in _events(bundle):
        body = event["payload"]["body"]
        event_hash = digest(event)
        if event_hash in required_by_hash:
            record = supplied[event_hash]
            proof, receipt = _sidecar(record, event, trust, expected_witness_hash, expected_authority_hash)
            received = milliseconds(receipt["received_at"])
            if (
                proof["witness_sequence"] <= last_sequence
                or proof["consumption_index"] <= last_consumption
                or (last_received is not None and received < last_received)
            ):
                raise ClosureError("TIME_ASSURANCE_ORDERING_INVALID")
            last_sequence, last_consumption, last_received = (
                proof["witness_sequence"],
                proof["consumption_index"],
                received,
            )
            if (
                proof["nonce"] in nonce_set
                or proof["witness_sequence"] in sequence_set
                or proof["consumption_index"] in consumption_set
            ):
                raise ClosureError("TIME_ASSURANCE_REPLAYED_RECEIPT")
            nonce_set.add(proof["nonce"])
            sequence_set.add(proof["witness_sequence"])
            consumption_set.add(proof["consumption_index"])
            if body["state"] == "ACCEPTED":
                if record["subject"] != packets.get(body["transaction_id"]):
                    raise ClosureError("TIME_ASSURANCE_CLOSURE_NOT_ADMITTED")
            if body["state"] in {"RECOVERY_FAILED", "RECOVERED"}:
                parent = packets.get(body["transaction_id"])
                if parent is None:
                    raise ClosureError("TIME_ASSURANCE_RECOVERY_PARENT_MISSING")
                from .protocol import strict_loads

                inputs = strict_loads(store.get(parent["payload"]["body"]["inputs_hash"]))
                child = None
                observed = milliseconds(receipt["received_at"])
                if body["packet"] is not None:
                    if milliseconds(body["packet"]["payload"]["body"]["evaluated_at"]) > observed:
                        raise ClosureError("WITNESS_GATE_CHILD_EVALUATION_NOT_OBSERVED")
                    child = freeze(body["recovery_contract"], body["recovery_approval"], trust)
                recovered = recovery_status(
                    parent,
                    child,
                    body["packet"],
                    trust,
                    observed,
                    inputs["contract"]["recovery"]["deadline_ms"],
                    store=store,
                )
                if recovered["state"] != body["state"]:
                    raise ClosureError("TIME_ASSURANCE_RECOVERY_NOT_OBSERVED")
            summaries.append(
                {
                    "event_hash": event_hash,
                    "state": body["state"],
                    "transaction_id": body["transaction_id"],
                    "received_at": receipt["received_at"],
                    "subject_purpose": proof["subject_purpose"],
                }
            )
        if body["state"] in VERDICTS:
            packets[body["transaction_id"]] = body["packet"]
    return {
        "version": VERSION,
        "technical": closure,
        "time_assurance": {
            "status": "HISTORICAL_WITNESSED",
            "witness_hash": expected_witness_hash,
            "authority_hash": expected_authority_hash,
            "events": summaries,
            "scope": "TECHNICAL_TERMINAL_AND_SELECTED_ACCEPTANCE_OR_RECOVERY",
            "clock_claim": "ENROLLED_WITNESS_SYSTEM_UTC_NOT_ABSOLUTE_UTC",
            "current_target_state": "NOT_OBSERVED",
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", required=True)
    parser.add_argument("--expected-authority-hash", required=True)
    parser.add_argument("--expected-witness-hash", required=True)
    parser.add_argument("--expected-transaction", required=True)
    parser.add_argument("--expected-contract-hash", required=True)
    parser.add_argument("--expected-artifact-hash", required=True)
    parser.add_argument("--prior-checkpoint")
    args = parser.parse_args(argv)
    try:
        import json

        result = verify_time_assurance(
            read_bundle(args.proof),
            expected_authority_hash=args.expected_authority_hash,
            expected_witness_hash=args.expected_witness_hash,
            expected_transaction=args.expected_transaction,
            expected_contract_hash=args.expected_contract_hash,
            expected_artifact_hash=args.expected_artifact_hash,
            prior_checkpoint=read_bundle(args.prior_checkpoint) if args.prior_checkpoint else None,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except ClosureError as exc:
        print(str(exc.code), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print("TIME_ASSURANCE_INPUT_ERROR:" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
