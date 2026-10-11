"""Deterministic admission and aggregation; no model, network, or side effects."""

from dataclasses import asdict, dataclass

from .contracts import freeze
from .crypto import sign, verify
from .protocol import POLICY_HASH, ClosureError, digest, milliseconds, timestamp


@dataclass(frozen=True)
class Evaluation:
    verdict: str
    reason_codes: list
    checks: dict
    admitted: list
    rejected: list
    window_complete: bool
    recovery_required: bool

    def to_dict(self):
        return asdict(self)


def _match(body, reference, field, code):
    if body[field] != reference[field]:
        raise ClosureError(code)


def evaluate(frozen, binding, records, receipts, store, trust, now):
    # Revalidate the immutable approval/trust relationship at every boundary.
    freeze(frozen.data, frozen.approval, trust)
    c = frozen.data
    b = verify(binding, "run-binding", trust)
    ref = {
        "contract_hash": frozen.hash,
        "transaction_id": c["transaction_id"],
        "attempt_id": c["attempt_id"],
        "target_id": c["target_id"],
    }
    for field, code in [
        ("contract_hash", "CONTRACT_MISMATCH"),
        ("transaction_id", "TRANSACTION_MISMATCH"),
        ("attempt_id", "ATTEMPT_MISMATCH"),
        ("target_id", "TARGET_MISMATCH"),
    ]:
        _match(b, ref, field, code)
    if isinstance(now, bool) or not isinstance(now, int):
        raise ClosureError("UNTRUSTED_EVALUATION_TIME")
    start = milliseconds(b["window_start"])
    skew = c["window"]["max_clock_skew_ms"]
    if milliseconds(binding["payload"]["created_at"]) > now + skew:
        raise ClosureError("FUTURE_RUN_BINDING")
    if len({p["nonce"] for p in b["challenges"]}) != len(b["challenges"]):
        raise ClosureError("DUPLICATE_CHALLENGE")
    challenges = {p["nonce"]: p for p in b["challenges"]}
    ref.update(artifact_hash=b["artifact_hash"])
    checks = {ch["id"]: ch for ch in c["checks"]}
    admitted, rejected, observations = {}, {}, {key: [] for key in checks}
    seen_ids, consumed_nonces, conflicted_checks = {}, {}, set()
    receipt_states, receipt_hashes, receipt_ids = set(), set(), {}
    receipt_conflict = False
    for envelope in sorted(receipts, key=digest):
        h = digest(envelope)
        try:
            body = verify(envelope, "action-receipt", trust)
            for field, code in [
                ("contract_hash", "CONTRACT_MISMATCH"),
                ("artifact_hash", "ARTIFACT_MISMATCH"),
                ("transaction_id", "TRANSACTION_MISMATCH"),
                ("attempt_id", "ATTEMPT_MISMATCH"),
                ("target_id", "TARGET_MISMATCH"),
            ]:
                _match(body, ref, field, code)
            if body["operation"] not in c["allowed_actions"]:
                raise ClosureError("OPERATION_DENIED")
            existing_receipt = receipt_ids.get(body["receipt_id"])
            if existing_receipt is not None:
                if existing_receipt == h:
                    continue
                receipt_conflict = True
                raise ClosureError("RECEIPT_ID_CONFLICT")
            if (
                abs(milliseconds(envelope["payload"]["created_at"]) - milliseconds(body["recorded_at"]))
                > skew
            ):
                raise ClosureError("RECEIPT_TIMESTAMP_MISMATCH")
            age = now - milliseconds(body["recorded_at"])
            if age < -skew:
                raise ClosureError("FUTURE_EVIDENCE")
            if age > c["window"]["max_age_ms"]:
                raise ClosureError("STALE_EVIDENCE")
            receipt_states.add(body["status"])
            receipt_hashes.add(h)
            receipt_ids[body["receipt_id"]] = h
        except ClosureError as exc:
            rejected[h] = exc.code
    if len(receipt_states) != 1 or receipt_conflict:
        receipt_state = "UNKNOWN"
    else:
        receipt_state = next(iter(receipt_states))
    for pair in sorted(records, key=digest):
        h = digest(pair)
        if h in admitted or h in rejected:
            continue
        try:
            if set(pair) != {"observation", "ingestion"}:
                raise ClosureError("SCHEMA_INVALID")
            envelope = pair["observation"]
            body = verify(envelope, "observation", trust)
            ingestion = verify(pair["ingestion"], "ingestion", trust)
            if ingestion["envelope_hash"] != digest(envelope):
                raise ClosureError("INGESTION_MISMATCH")
            check = checks.get(body["check_id"])
            if check is None:
                raise ClosureError("UNKNOWN_CHECK")
            observation_ref = dict(ref)
            if check["kind"] == "baseline":
                observation_ref["artifact_hash"] = c["baseline_hash"]
            for field, code in [
                ("contract_hash", "CONTRACT_MISMATCH"),
                ("artifact_hash", "ARTIFACT_MISMATCH"),
                ("transaction_id", "TRANSACTION_MISMATCH"),
                ("attempt_id", "ATTEMPT_MISMATCH"),
                ("target_id", "TARGET_MISMATCH"),
            ]:
                _match(body, observation_ref, field, code)
            identity = envelope["payload"]["issuer"]
            enrollment = trust.record(envelope["payload"]["key_id"])
            if identity not in check["observers"] or body["check_id"] not in enrollment["checks"]:
                raise ClosureError("OBSERVER_NOT_AUTHORIZED")
            if body["evaluator_hash"] != c["evaluator_hash"]:
                raise ClosureError("EVALUATOR_MISMATCH")
            if body["policy_hash"] != POLICY_HASH:
                raise ClosureError("POLICY_MISMATCH")
            challenge = challenges.get(body["nonce"])
            if (
                challenge is None
                or challenge["check_id"] != body["check_id"]
                or (challenge["phase"] != body["phase"] or body["phase"] != check["phase"])
            ):
                raise ClosureError("CHALLENGE_MISMATCH")
            observed = milliseconds(body["observed_at"])
            received = milliseconds(ingestion["received_at"])
            if abs(milliseconds(envelope["payload"]["created_at"]) - observed) > skew or (
                abs(milliseconds(pair["ingestion"]["payload"]["created_at"]) - received) > skew
            ):
                raise ClosureError("OBSERVATION_TIMESTAMP_MISMATCH")
            if observed > now + skew or received > now + skew or received < observed - skew:
                raise ClosureError("FUTURE_EVIDENCE")
            if observed < milliseconds(binding["payload"]["created_at"]) - skew:
                raise ClosureError("PRE_BINDING_EVIDENCE")
            if now - observed > c["window"]["max_age_ms"] or now - received > c["window"]["max_age_ms"]:
                raise ClosureError("STALE_EVIDENCE")
            if body["result"] == "NOT_COMPLETED" and not check["allow_not_completed"]:
                raise ClosureError("INVALID_PARTIAL_RESULT")
            evidence = store.get(body["evidence_hash"])
            if check["kind"] == "baseline" and digest(evidence) != c["baseline_hash"]:
                raise ClosureError("BASELINE_EVIDENCE_MISMATCH")
            obs_hash = digest(envelope)
            if body["observation_id"] in seen_ids or body["nonce"] in consumed_nonces:
                if seen_ids.get(body["observation_id"]) == obs_hash and (
                    consumed_nonces.get(body["nonce"]) == obs_hash
                ):
                    continue
                conflicted_checks.add(body["check_id"])
                raise ClosureError("REPLAYED_OR_CONFLICTING_OBSERVATION")
            seen_ids[body["observation_id"]] = obs_hash
            consumed_nonces[body["nonce"]] = obs_hash
            observations[body["check_id"]].append(body)
            admitted[h] = body
        except ClosureError as exc:
            rejected[h] = exc.code
    outcomes = {}
    known_failure = False
    tamper = False
    end = start + c["window"]["duration_ms"]
    window_complete = now >= end and now <= milliseconds(c["deadline_at"]) and now >= start
    for key, check in checks.items():
        samples = observations[key]
        results = {s["result"] for s in samples}
        check_tamper = any(s["tamper_detected"] for s in samples)
        if "FAIL" in results or check_tamper:
            outcomes[key] = "FAIL"
            known_failure |= check["mandatory"]
            tamper |= check_tamper
        elif not samples or key in conflicted_checks or "UNKNOWN" in results or len(results) != 1:
            outcomes[key] = "UNKNOWN"
        elif check["phase"] == "window":
            times = sorted({milliseconds(s["observed_at"]) for s in samples})
            inside = all(start <= t <= end for t in times)
            coverage = times[0] <= start + skew and times[-1] >= end - skew
            gaps = all(y - x <= c["window"]["max_gap_ms"] for x, y in zip(times, times[1:]))
            passed = (
                window_complete and inside and coverage and gaps and len(times) >= c["window"]["min_samples"]
            )
            outcomes[key] = next(iter(results)) if passed else "UNKNOWN"
        else:
            outcomes[key] = next(iter(results))
    required = [outcomes[k] for k, ch in checks.items() if ch["mandatory"]]
    reason_codes = []
    if known_failure or tamper:
        verdict = "DISPROVEN"
        reason_codes = ["EVALUATOR_TAMPER" if tamper else "MANDATORY_CHECK_FAILED"]
    elif "UNKNOWN" in required or receipt_state == "UNKNOWN" or not window_complete:
        verdict = "INDETERMINATE"
        reason_codes = ["REQUIRED_EVIDENCE_UNRESOLVED"]
    elif "NOT_COMPLETED" in required:
        if receipt_state == "NOT_DEPLOYED" and any(
            outcomes[k] == "PASS" for k, ch in checks.items() if ch["kind"] == "stage"
        ):
            verdict, reason_codes = "PARTIALLY_PROVEN", ["CONFIRMED_NON_COMPLETION"]
        else:
            verdict, reason_codes = "INDETERMINATE", ["CONFLICTING_EXECUTION_EVIDENCE"]
    elif receipt_state == "EXECUTED" and all(v == "PASS" for v in required):
        verdict = "PROVEN"
    else:
        verdict, reason_codes = "INDETERMINATE", ["CONFLICTING_EXECUTION_EVIDENCE"]
    return Evaluation(
        verdict,
        reason_codes,
        outcomes,
        sorted(list(admitted) + list(receipt_hashes)),
        [{"hash": h, "reason": rejected[h]} for h in sorted(rejected)],
        window_complete,
        verdict != "PROVEN" and receipt_state != "NOT_DEPLOYED",
    )


def close_run(*, authority, ledger_head, **args):
    # Compute here; callers cannot submit an arbitrary verdict for signing.
    result = evaluate(**args)
    c = args["frozen"].data
    b = verify(args["binding"], "run-binding", args["trust"])
    body = {
        "transaction_id": c["transaction_id"],
        "attempt_id": c["attempt_id"],
        "contract_hash": args["frozen"].hash,
        "approval_hash": digest(args["frozen"].approval),
        "artifact_hash": b["artifact_hash"],
        "baseline_hash": c["baseline_hash"],
        "target_id": c["target_id"],
        "evaluator_hash": c["evaluator_hash"],
        "policy_hash": POLICY_HASH,
        "trust_hash": args["trust"].hash,
        "binding_hash": digest(args["binding"]),
        "ledger_head": ledger_head,
        "evaluated_at": timestamp(args["now"]),
        "window_start": b["window_start"],
        "window_end": timestamp(milliseconds(b["window_start"]) + c["window"]["duration_ms"]),
        "parent_packet_hash": c["parent_packet_hash"],
        **result.to_dict(),
    }
    packet = sign(authority, "closure-packet", body, timestamp(args["now"]))
    verify(packet, "closure-packet", args["trust"])
    return packet
