"""Portable, public-only custody proof and offline verification with an independent trust pin.

The container is ordinary bounded JSON. Every signed protocol item keeps the kernel's own
canonicalization/size limits. Verification invokes the existing ledger and verdict replay;
bundled public keys never authorize themselves, and this module holds no signing key.
"""

import argparse
import base64
import binascii
import hmac
import json
import re
import sys
from pathlib import Path

from ..crypto import TrustStore
from ..protocol import ACCEPTED_POLICIES, MAX_BYTES, ClosureError, canonical, digest, strict_loads
from .export import replay_audit_export

VERSION = "ace.portable.v2"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_OBJECTS = 8192
HASH = re.compile(r"sha256:[0-9a-f]{64}")
RUN_FIELDS = {"mode", "contract", "approval", "binding", "records", "receipts"}
PROOF_FIELDS = {"version", "transaction_id", "trust", "pages", "evaluators", "policies", "evidence", "scope"}


def _required_scope(contracts, events, transaction):
    """Requested subject plus cryptographically linked recovery ancestors/children only."""
    by_transaction = {item["contract"]["transaction_id"]: item for item in contracts}
    packet_subjects = {}
    for event in events:
        packet = event["payload"]["body"].get("packet")
        if packet:
            packet_subjects[digest(packet)] = packet["payload"]["body"]["transaction_id"]
    scope, pending = set(), [transaction]
    while pending:
        subject = pending.pop()
        if subject in scope:
            continue
        if subject not in by_transaction:
            raise ClosureError("EXPORT_SCOPE_MISMATCH")
        scope.add(subject)
        parent = by_transaction[subject]["contract"]["parent_packet_hash"]
        if parent is not None:
            if parent not in packet_subjects:
                raise ClosureError("RECOVERY_PARENT_MISSING")
            pending.append(packet_subjects[parent])
        for event in events:
            body = event["payload"]["body"]
            if body["transaction_id"] == subject and body.get("recovery_contract"):
                pending.append(body["recovery_contract"]["transaction_id"])
    return sorted(scope)


def _input_references(manifest):
    """Follow defined custody relationships, never arbitrary hashes inside artifact/probe bytes."""
    contract = manifest["contract"]
    yield contract["evaluator_hash"], "opaque"
    yield contract["baseline_hash"], "opaque"
    yield manifest["binding"]["payload"]["body"]["artifact_hash"], "opaque"
    for pair in manifest["records"]:
        observation = pair.get("observation", {}) if isinstance(pair, dict) else {}
        payload = observation.get("payload", {}) if isinstance(observation, dict) else {}
        body = payload.get("body", {}) if isinstance(payload, dict) else {}
        if not isinstance(body, dict) or any(
            body.get(field) != expected
            for field, expected in (
                ("transaction_id", contract["transaction_id"]),
                ("attempt_id", contract["attempt_id"]),
                ("target_id", contract["target_id"]),
                ("contract_hash", digest(contract)),
            )
        ):
            # Retained rejected inputs remain available as signed input metadata. A foreign
            # observation rejected before evidence admission must not authorize raw-byte export.
            continue
        if "evidence_hash" in body:
            yield body["evidence_hash"], "opaque"


def export_bundle(custody, transaction):
    """Export an unchanged evaluator input plus all public material needed for offline replay.

    Global signed envelopes authenticate membership/order but do not pull foreign artifact
    bytes into a transaction download. Raw evidence is scoped to the selected transaction
    and required recovery relationships. Foreign outcome semantics remain NOT_EVALUATED.
    """
    meta = custody.tx(transaction)
    if meta["binding"] is None:
        raise ClosureError("RUN_BINDING_REQUIRED", transaction)
    bundle = {
        "mode": "runtime",
        "contract": meta["contract"],
        "approval": meta["approval"],
        "binding": meta["binding"],
        "records": custody.records(transaction),
        "receipts": custody.receipts(transaction),
    }
    pages, start, position = [], 1, None
    while True:
        page = custody.audit_export(start, 64)
        body = page["checkpoint"]["payload"]["body"]
        current = (body["head_hash"], body["sequence"])
        if position is not None and current != position:
            raise ClosureError("EXPORT_SNAPSHOT_CHANGED")
        position = current
        pages.append(page)
        if len(pages) > 1024:
            raise ClosureError("PORTABLE_BUNDLE_TOO_LARGE")
        if page["next_sequence"] is None:
            break
        start = page["next_sequence"]
    trust = TrustStore.from_dict(pages[0]["trust"])
    if trust.hash != pages[0]["trust_hash"]:
        raise ClosureError("EXPORT_TRUST_MISMATCH")
    events = [event for page in pages for event in page["events"]]
    scope = _required_scope(pages[0]["contracts"], events, transaction)
    scoped_contracts = [item for item in pages[0]["contracts"] if item["contract"]["transaction_id"] in scope]
    # Foreign signed event metadata is retained for chain authentication. Foreign contracts,
    # evaluator expectations and raw artifacts/observations are not part of this download.
    for page in pages:
        page["contracts"] = scoped_contracts
    evidence, visited = {}, set()
    todo = list(_input_references(bundle))
    for item in scoped_contracts:
        todo.extend(
            [(item["contract"]["evaluator_hash"], "opaque"), (item["contract"]["baseline_hash"], "opaque")]
        )
    for event in events:
        body = event["payload"]["body"]
        if body["transaction_id"] not in scope:
            continue
        todo.extend((ref, "baseline" if body["state"] == "BASELINED" else "opaque") for ref in body["refs"])
        if body.get("binding"):
            todo.append((body["binding"]["payload"]["body"]["artifact_hash"], "opaque"))
        if body.get("packet"):
            todo.append((body["packet"]["payload"]["body"]["inputs_hash"], "inputs"))
    while todo:
        reference, kind = todo.pop()
        if (reference, kind) in visited:
            continue
        visited.add((reference, kind))
        raw = custody.evidence_get(reference)
        if digest(raw) != reference:
            raise ClosureError("EVIDENCE_HASH_MISMATCH", reference)
        evidence[reference] = base64.b64encode(raw).decode("ascii")
        if len(evidence) > MAX_OBJECTS:
            raise ClosureError("PORTABLE_BUNDLE_TOO_LARGE")
        if kind == "inputs":
            todo.extend(_input_references(strict_loads(raw)))
        elif kind == "baseline":
            manifest = strict_loads(raw)
            todo.append((manifest["artifact_hash"], "opaque"))
            todo.extend((ref, "opaque") for ref in manifest["protected"].values())
    evaluators = {}
    policies = {}
    for item in pages[0]["contracts"]:
        contract = item["contract"]
        reference = contract["evaluator_hash"]
        if reference not in evidence:
            raise ClosureError("EVIDENCE_MISSING", reference)
        evaluators[reference] = strict_loads(base64.b64decode(evidence[reference], validate=True))
        policy = contract["policy_hash"]
        if policy not in ACCEPTED_POLICIES:
            raise ClosureError("POLICY_MISMATCH")
        policies[policy] = ACCEPTED_POLICIES[policy]
    bundle["portable"] = {
        "version": VERSION,
        "transaction_id": transaction,
        "scope": {
            "mode": "transaction",
            "transactions": scope,
            "global_chain": "SIGNATURES_HASH_LINKS_CHRONOLOGY_CHECKPOINT",
            "foreign_transaction_semantics": "NOT_EVALUATED",
        },
        "trust": trust.data,
        "pages": pages,
        "evaluators": evaluators,
        "policies": policies,
        "evidence": evidence,
    }
    # Bound the download rather than relaxing any signed protocol object's limits.
    encode_bundle(bundle)
    return bundle


def encode_bundle(bundle):
    try:
        raw = json.dumps(bundle, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise ClosureError("PORTABLE_BUNDLE_INVALID") from exc
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ClosureError("PORTABLE_BUNDLE_TOO_LARGE")
    return raw + b"\n"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ClosureError("DUPLICATE_KEY")
        value[key] = item
    return value


def read_bundle(path):
    """Read a bounded container without mistaking its aggregate size for a protocol item size."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BUNDLE_BYTES + 2)
    if len(raw) > MAX_BUNDLE_BYTES + 1:
        raise ClosureError("PORTABLE_BUNDLE_TOO_LARGE")
    try:
        return json.loads(raw, object_pairs_hook=_unique)
    except ClosureError:
        raise
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ClosureError("PORTABLE_BUNDLE_INVALID") from exc


def verify_bundle(
    bundle,
    expected_trust_hash,
    *,
    prior_checkpoint=None,
    expected_transaction=None,
    expected_contract_hash=None,
    expected_artifact_hash=None,
):
    """Authenticate keys with an independently supplied pin, then replay the existing kernel.

    The caller may supply a previously retained signed checkpoint to additionally detect a
    rollback/fork. A trust pin alone authenticates signers, not the latest historical head.
    """
    if not isinstance(expected_trust_hash, str) or not HASH.fullmatch(expected_trust_hash):
        raise ClosureError("INVALID_TRUST_ANCHOR")
    if not isinstance(bundle, dict) or set(bundle) != RUN_FIELDS | {"portable"}:
        raise ClosureError("PORTABLE_BUNDLE_INVALID")
    proof = bundle["portable"]
    if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS or proof["version"] != VERSION:
        raise ClosureError("PORTABLE_BUNDLE_INVALID")
    trust = TrustStore.from_dict(proof["trust"])
    if not hmac.compare_digest(trust.hash, expected_trust_hash):
        raise ClosureError("TRUST_ANCHOR_MISMATCH")
    if (
        bundle["mode"] != "runtime"
        or proof["transaction_id"] != bundle["contract"]["transaction_id"]
        or not isinstance(proof["pages"], list)
        or not 1 <= len(proof["pages"]) <= 1024
        or not isinstance(proof["evidence"], dict)
        or len(proof["evidence"]) > MAX_OBJECTS
        or not isinstance(proof["evaluators"], dict)
        or len(proof["evaluators"]) > 512
    ):
        raise ClosureError("PORTABLE_BUNDLE_INVALID")
    for page in proof["pages"]:
        canonical(page)  # same limits as every signed protocol page
        if page.get("trust") != trust.data:
            raise ClosureError("EXPORT_TRUST_MISMATCH")
    events = [event for page in proof["pages"] for event in page["events"]]
    scope = _required_scope(proof["pages"][0]["contracts"], events, proof["transaction_id"])
    expected_scope = {
        "mode": "transaction",
        "transactions": scope,
        "global_chain": "SIGNATURES_HASH_LINKS_CHRONOLOGY_CHECKPOINT",
        "foreign_transaction_semantics": "NOT_EVALUATED",
    }
    if proof["scope"] != expected_scope or set(scope) != {
        item["contract"]["transaction_id"] for item in proof["pages"][0]["contracts"]
    }:
        raise ClosureError("EXPORT_SCOPE_MISMATCH")
    raw_evidence = {}
    total = 0
    for reference, encoded in proof["evidence"].items():
        if not HASH.fullmatch(reference) or not isinstance(encoded, str) or len(encoded) > 2 * MAX_BYTES:
            raise ClosureError("PORTABLE_EVIDENCE_INVALID")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ClosureError("PORTABLE_EVIDENCE_INVALID") from exc
        if len(raw) > MAX_BYTES or digest(raw) != reference:
            raise ClosureError("EVIDENCE_HASH_MISMATCH", reference)
        total += len(raw)
        if total > MAX_BUNDLE_BYTES:
            raise ClosureError("PORTABLE_BUNDLE_TOO_LARGE")
        raw_evidence[reference] = raw

    def fetch(reference):
        try:
            return raw_evidence[reference]
        except KeyError as exc:
            raise ClosureError("EVIDENCE_MISSING", reference) from exc

    expected_evaluators, expected_policies = {}, {}
    for item in proof["pages"][0]["contracts"]:
        contract = item["contract"]
        expected_evaluators[contract["evaluator_hash"]] = strict_loads(fetch(contract["evaluator_hash"]))
        policy = contract["policy_hash"]
        if policy not in ACCEPTED_POLICIES:
            raise ClosureError("POLICY_MISMATCH")
        expected_policies[policy] = ACCEPTED_POLICIES[policy]
    if (
        set(proof["evaluators"]) != set(expected_evaluators)
        or proof["policies"] != expected_policies
        or any(digest(value) != reference for reference, value in expected_evaluators.items())
        or any(
            canonical(proof["evaluators"][key]) != canonical(value)
            for key, value in expected_evaluators.items()
        )
    ):
        raise ClosureError("PORTABLE_POLICY_MISMATCH")
    # The outer legacy input is useful to older tools, but must be the exact retained input,
    # rather than an unsigned second representation of the approved intent/evidence.
    result = replay_audit_export(
        proof["pages"],
        trust,
        expected_trust_hash,
        fetch,
        prior_checkpoint=prior_checkpoint,
        transaction=proof["transaction_id"],
        transaction_scope=scope,
    )
    closure = result["closure"]
    for field, expected in (
        ("transaction_id", expected_transaction),
        ("contract_hash", expected_contract_hash),
        ("artifact_hash", expected_artifact_hash),
    ):
        if expected is not None and closure[field] != expected:
            raise ClosureError("PROOF_SUBJECT_MISMATCH", field)
    packet_inputs = None
    for page in proof["pages"]:
        for event in page["events"]:
            packet = event["payload"]["body"].get("packet")
            if packet and digest(packet) == closure["packet_hash"]:
                packet_inputs = strict_loads(fetch(packet["payload"]["body"]["inputs_hash"]))
    if packet_inputs is None or any(
        canonical(bundle[key]) != canonical(packet_inputs[key]) for key in RUN_FIELDS - {"mode"}
    ):
        raise ClosureError("PORTABLE_INPUTS_MISMATCH")
    return {
        "version": VERSION,
        "trust_hash": trust.hash,
        "checkpoint": proof["pages"][-1]["checkpoint"],
        "evidence_objects": len(raw_evidence),
        "external_prior_checkpoint_checked": prior_checkpoint is not None,
        **result,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify an ACE portable proof entirely offline")
    parser.add_argument("--bundle", required=True)
    parser.add_argument(
        "--expected-trust-hash",
        required=True,
        help="Operator-provided enrollment pin obtained outside this bundle",
    )
    parser.add_argument("--prior-checkpoint", help="Previously independently retained signed checkpoint")
    parser.add_argument("--expected-transaction", help="Independent expected transaction identifier")
    parser.add_argument("--expected-contract-hash", help="Independent expected frozen contract digest")
    parser.add_argument("--expected-artifact-hash", help="Independent expected deployed artifact digest")
    parser.add_argument("--require-proven", action="store_true")
    args = parser.parse_args(argv)
    try:
        prior = strict_loads(Path(args.prior_checkpoint).read_bytes()) if args.prior_checkpoint else None
        result = verify_bundle(
            read_bundle(args.bundle),
            args.expected_trust_hash,
            prior_checkpoint=prior,
            expected_transaction=args.expected_transaction,
            expected_contract_hash=args.expected_contract_hash,
            expected_artifact_hash=args.expected_artifact_hash,
        )
        print(json.dumps(result, sort_keys=True))
        return 3 if args.require_proven and result["closure"]["verdict"] != "PROVEN" else 0
    except ClosureError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        return 2
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"error": "PORTABLE_INPUT_ERROR", "type": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
