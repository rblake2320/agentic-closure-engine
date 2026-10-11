"""Operating runtime facade: drives real transactions through the deterministic kernel.

Verdicts come only from ``verdicts.close_run`` and admission only from ``Ledger`` (inside
custody); this module performs each role's work and never evaluates outcomes itself.

Each method uses exactly one role key, loaded from that role's own state root. The facade talks
to custody through a custody object: ``LocalCustody`` in one process, or ``RemoteCustody``
when every role runs as its own service and only custody holds the custodian key.
Broker-private state: intents/<intent>.json write-ahead records, targets/<slug>.token.
"""

import secrets
import time
from pathlib import Path

from ..contracts import freeze
from ..crypto import sign
from ..protocol import (
    MAX_BYTES,
    POLICY_HASH,
    ClosureError,
    canonical,
    digest,
    milliseconds,
    strict_loads,
    timestamp,
)
from ..recovery import recovery_status
from ..verdicts import close_run
from . import evaluator
from .clock import SystemClock
from .custody import LocalCustody
from .deployment import Deployment
from .files import create_json, read_json, replace_json
from .target import TargetClient, json_pointer

SUBJECT = ("transaction_id", "attempt_id", "contract_hash", "artifact_hash", "target_id")


def _bounded_bytes(raw, code="ARTIFACT_INVALID"):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        raise ClosureError(code)
    return raw


class Runtime:
    def __init__(self, root, expected_trust_hash, *, clock=None, role_roots=None, custody=None):
        self.deployment = root if isinstance(root, Deployment) else Deployment(root, role_roots)
        self.trust = self.deployment.load_trust(expected_trust_hash)
        self.clock = clock or SystemClock()
        self.custody = (
            custody if custody is not None else LocalCustody(self.deployment, self.trust, self.clock)
        )

    @property
    def store(self):
        return self.custody.store

    # ----- helpers -------------------------------------------------------------------------
    def _identity(self, role):
        return self.deployment.identity(role, self.trust)

    def _issuer(self, role):
        """Issuer of the enrolled key for ``role`` (public enrollment; no private key needed)."""
        issuers = [k["issuer"] for k in self.trust.data["keys"] if k["role"] == role]
        if len(issuers) != 1:
            raise ClosureError("ROLE_NOT_ENROLLED", role)
        return issuers[0]

    def _tx(self, tx):
        return self.custody.tx(tx)

    def _frozen(self, meta):
        return freeze(meta["contract"], meta["approval"], self.trust)

    def _append(self, role, tx, state, **fields):
        identity = self._identity(role)
        meta = self._tx(tx)
        head, sequence = self.custody.position()
        body = {
            "event_id": "evt-" + secrets.token_hex(12),
            "transaction_id": tx,
            "contract_hash": digest(meta["contract"]),
            "sequence": sequence + 1,
            "previous_hash": head,
            "state": state,
            "refs": fields.get("refs", []),
            "packet": fields.get("packet"),
            "binding": fields.get("binding"),
            "receipt": fields.get("receipt"),
            "recovery_contract": fields.get("recovery_contract"),
            "recovery_approval": fields.get("recovery_approval"),
            "risk": None,
        }
        return self.custody.append(sign(identity, "ledger-event", body, self.clock.now()), head)

    def _profile(self, target_id):
        return self.deployment.target(target_id)

    def _client(self, target_id, with_token=False):
        token = None
        if with_token:
            path = self.deployment.target_token_path(target_id)
            try:
                token = path.read_bytes().decode()
            except FileNotFoundError as exc:
                raise ClosureError("DEPLOY_CREDENTIAL_MISSING", target_id) from exc
        return TargetClient(self._profile(target_id), token)

    def checkpoint(self):
        """Signed head for export to independent custody (store it outside this deployment)."""
        return self.custody.checkpoint()

    # ----- actor ---------------------------------------------------------------------------
    def propose(
        self,
        target_id,
        transaction_id,
        artifact,
        *,
        intent,
        duration_ms=60_000,
        min_samples=3,
        max_clock_skew_ms=2_000,
        settle_ms=3_000,
        deadline_ms=600_000,
        recovery_deadline_ms=600_000,
        repo_id="ace/runtime",
        allowed_changes=("artifact",),
        expect=None,
        allow_partial=False,
        parent=None,
        parent_transaction=None,
    ):
        """Actor: stage the artifact and draft a contract from the enrolled target profile.

        ``expect`` maps each primary check id to the owner's desired JSON value. The value the
        target serves today is read as the restoration criterion. Both are frozen into the
        evaluator bundle the owner approves; the verifier confirms the current value at baseline.
        """
        self._identity("actor")
        artifact = _bounded_bytes(artifact)
        if self.custody.exists(transaction_id):
            raise ClosureError("TRANSACTION_ALREADY_EXISTS", transaction_id)
        if type(min_samples) is not int or min_samples < 2:
            raise ClosureError("INVALID_WINDOW")
        profile = self._profile(target_id)
        client = self._client(target_id)
        state = client.state()
        current = client.artifact()
        if digest(current) != state["artifact_hash"]:
            raise ClosureError("TARGET_STATE_INCONSISTENT")
        if parent is None:
            restore = {}
            for check in evaluator.criteria_checks(profile):
                status, raw = client.get(check["probe"]["path"])
                if status != 200:
                    raise ClosureError("PRIMARY_UNAVAILABLE", check["id"])
                restore[check["id"]] = json_pointer(strict_loads(raw), check["probe"]["pointer"])
            bundle_hash = self.store.put(canonical(evaluator.build(profile, expect, restore)))
        else:
            if expect is not None:
                raise ClosureError("RECOVERY_CRITERIA_ARE_INHERITED")
            bundle_hash = parent["evaluator_hash"]
        verifier = self._issuer("verifier")
        checks = [
            {
                "id": c["id"],
                "kind": c["kind"],
                "phase": c["phase"],
                "mandatory": c["mandatory"],
                "observers": [verifier],
                # Primary opt-in (policy v3): a confirmed non-deployment may be PARTIALLY_PROVEN.
                "allow_not_completed": c["kind"] == "deployment"
                or (c["kind"] == "primary" and allow_partial is True),
            }
            for c in profile["checks"]
        ]
        gap = -(-duration_ms // (min_samples - 1))
        now = self.clock.now_ms()
        contract = {
            "version": "v1",
            "contract_id": transaction_id,
            "revision": 1,
            "transaction_id": transaction_id,
            "attempt_id": transaction_id + "/attempt-1",
            "repo_id": repo_id,
            "baseline_hash": state["artifact_hash"],
            "target_id": target_id,
            "intent": intent,
            "allowed_changes": list(allowed_changes),
            "protected_resources": [c["id"] for c in checks if c["kind"] == "invariant"],
            "allowed_actions": ["deploy"],
            "evaluator_hash": bundle_hash,
            "policy_hash": POLICY_HASH,
            "trust_hash": self.trust.hash,
            "deadline_at": timestamp(now + deadline_ms),
            "checks": checks,
            "window": {
                "duration_ms": duration_ms,
                "max_gap_ms": gap,
                "min_samples": min_samples,
                "max_age_ms": max(deadline_ms, duration_ms + settle_ms + 60_000),
                "max_clock_skew_ms": max_clock_skew_ms,
            },
            "recovery": {"mechanism": "redeploy-baseline", "deadline_ms": recovery_deadline_ms},
            "parent_packet_hash": None,
        }
        if parent is not None:
            contract.update(parent)
        proposal = {
            "transaction_id": transaction_id,
            "target_id": target_id,
            "contract": contract,
            "artifact_hash": self.store.put(artifact),
            "current_baseline_hash": self.store.put(current),
            "settle_ms": settle_ms,
        }
        return self.custody.create_tx(proposal, parent_transaction)

    def begin_recovery(self, tx):
        """Actor: draft the child transaction that restores the parent's baseline artifact."""
        meta = self._tx(tx)
        packet = meta.get("verdict_packet")
        if self.custody.state(tx) != "RECOVERY_REQUIRED" or packet is None:
            raise ClosureError("RECOVERY_NOT_REQUIRED", str(self.custody.state(tx)))
        parent_contract = meta["contract"]
        window = parent_contract["window"]
        inherited = {
            "checks": [dict(c) for c in parent_contract["checks"]],
            "protected_resources": list(parent_contract["protected_resources"]),
            "window": dict(window),
            "evaluator_hash": parent_contract["evaluator_hash"],
            "parent_packet_hash": digest(packet),
            "intent": "Restore baseline after " + packet["payload"]["body"]["verdict"] + " for " + tx,
        }
        return self.propose(
            meta["target_id"],
            tx + "/recovery",
            self.store.get(parent_contract["baseline_hash"]),
            intent=inherited["intent"],
            duration_ms=window["duration_ms"],
            min_samples=window["min_samples"],
            max_clock_skew_ms=window["max_clock_skew_ms"],
            settle_ms=meta["settle_ms"],
            parent=inherited,
            parent_transaction=tx,
        )

    # ----- owner ---------------------------------------------------------------------------
    def approve(self, tx):
        """Owner: sign the exact contract hash; custody registers it; record DRAFT and APPROVED."""
        meta = self._tx(tx)
        body = {
            "contract_hash": digest(meta["contract"]),
            "trust_hash": self.trust.hash,
            "policy_hash": POLICY_HASH,
        }
        approval = sign(self._identity("owner"), "approval", body, self.clock.now())
        self.custody.set_approval(tx, approval)
        self._append("owner", tx, "DRAFT")
        self._append("owner", tx, "APPROVED")
        return self.status(tx)

    def accept(self, tx):
        """Owner: separate acceptance of a PROVEN technical verdict."""
        self._append("owner", tx, "ACCEPTED")
        return self.status(tx)

    # ----- authority -----------------------------------------------------------------------
    def freeze(self, tx):
        self._frozen(self._tx(tx))
        self._append("authority", tx, "FROZEN")
        return self.status(tx)

    def bind(self, tx):
        """Authority: issue the run binding (artifact, challenges, window start)."""
        meta = self._tx(tx)
        contract = meta["contract"]
        now = self.clock.now_ms()
        challenges = []
        for check in contract["checks"]:
            # Window checks get twice the frozen minimum minus one challenges: the verifier can
            # sample at half the maximum gap, giving scheduling headroom without changing the
            # contract's duration, max_gap, min_samples or skew obligations.
            count = 2 * contract["window"]["min_samples"] - 1 if check["phase"] == "window" else 1
            for _ in range(count):
                challenges.append(
                    {"nonce": "n-" + secrets.token_hex(12), "check_id": check["id"], "phase": check["phase"]}
                )
        body = {
            "transaction_id": tx,
            "attempt_id": contract["attempt_id"],
            "contract_hash": digest(contract),
            "artifact_hash": meta["artifact_hash"],
            "target_id": meta["target_id"],
            "window_start": timestamp(now + meta["settle_ms"]),
            "challenges": challenges,
        }
        binding = sign(self._identity("authority"), "run-binding", body, timestamp(now))
        self.custody.set_binding(tx, binding)
        return dict(self.status(tx), binding_hash=digest(binding))

    def _close_packet(self, meta, now_ms):
        return close_run(
            frozen=self._frozen(meta),
            binding=meta["binding"],
            records=self.custody.records(meta["transaction_id"]),
            receipts=self.custody.receipts(meta["transaction_id"]),
            store=self.store,
            trust=self.trust,
            now=now_ms,
            authority=self._identity("authority"),
            ledger_head=self.custody.position()[0],
        )

    def close(self, tx):
        """Authority: deterministic evaluation via close_run; append exactly what it decided."""
        meta = self._tx(tx)
        state = self.custody.state(tx)
        if meta["binding"] is None or state not in {"EXECUTING", "VERIFYING", "OBSERVING"}:
            raise ClosureError("NOT_CLOSABLE", str(state))
        contract = meta["contract"]
        window_end = (
            milliseconds(meta["binding"]["payload"]["body"]["window_start"])
            + contract["window"]["duration_ms"]
        )
        if state == "VERIFYING":
            packet = self._close_packet(meta, self.clock.now_ms())
            body = packet["payload"]["body"]
            instant = [c["id"] for c in contract["checks"] if c["mandatory"] and c["phase"] == "instant"]
            if all(body["checks"].get(c) == "PASS" for c in instant) and body["verdict"] != "DISPROVEN":
                self._append("authority", tx, "OBSERVING", packet=packet)
                if self.clock.now_ms() < window_end:
                    return dict(self.status(tx), immediate=body["checks"])
                return self._record_verdict(tx, self._close_packet(self._tx(tx), self.clock.now_ms()))
            if body["verdict"] != "DISPROVEN" and self.clock.now_ms() < window_end:
                # No known failure yet and instant checks unresolved (e.g. confirmed non-deployment):
                # the frozen window must complete before any verdict is recorded.
                raise ClosureError("OBSERVATION_WINDOW_OPEN", timestamp(window_end))
            return self._record_verdict(tx, packet)
        if state == "OBSERVING" and self.clock.now_ms() < window_end:
            raise ClosureError("OBSERVATION_WINDOW_OPEN", timestamp(window_end))
        return self._record_verdict(tx, self._close_packet(meta, self.clock.now_ms()))

    def _record_verdict(self, tx, packet):
        body = packet["payload"]["body"]
        self._append("authority", tx, body["verdict"], packet=packet)
        if body["recovery_required"]:
            self._append("authority", tx, "RECOVERY_REQUIRED")
        return dict(
            self.status(tx),
            verdict=body["verdict"],
            reason_codes=body["reason_codes"],
            packet_hash=digest(packet),
        )

    def complete_recovery(self, tx):
        """Authority: submit the closed child packet; the kernel decides RECOVERED/FAILED."""
        meta = self._tx(tx)
        child = self._tx(meta["child_transaction"]) if meta.get("child_transaction") else {}
        packet = child.get("verdict_packet")
        status = recovery_status(
            meta["verdict_packet"],
            self._frozen(child) if packet else None,
            packet,
            self.trust,
            self.clock.now_ms(),
            meta["contract"]["recovery"]["deadline_ms"],
            store=self.store,
        )
        if status["state"] == "RECOVERY_REQUIRED":
            return dict(self.status(tx), recovery=status)
        self._append(
            "authority",
            tx,
            status["state"],
            packet=packet,
            recovery_contract=child["contract"] if packet else None,
            recovery_approval=child["approval"] if packet else None,
        )
        return dict(self.status(tx), recovery=status)

    # ----- verifier ------------------------------------------------------------------------
    def baseline(self, tx):
        """Verifier: read the target's current protected state and retain it in custody."""
        self._identity("verifier")
        meta = self._tx(tx)
        contract = meta["contract"]
        client = self._client(meta["target_id"])
        state = client.state()
        if state["artifact_hash"] != contract["baseline_hash"]:
            raise ClosureError("BASELINE_PRECONDITION_FAILED", state["artifact_hash"])
        bundle = self._evaluator(meta)
        if meta["parent_transaction"] is not None:
            # Recovery restores the parent's protected state, not today's possibly damaged state.
            protected = self.custody.manifest(meta["parent_transaction"])["protected"]
        else:
            # Independently confirm the owner-approved restoration value is what is live now.
            for check in evaluator.criteria_checks(bundle["profile"]):
                status, raw = client.get(check["probe"]["path"])
                try:
                    live = (
                        json_pointer(strict_loads(raw), check["probe"]["pointer"]) if status == 200 else None
                    )
                except ClosureError:
                    live = None
                restore = bundle["criteria"][check["id"]]["restore_equals"]
                if status != 200 or canonical(live) != canonical(restore):
                    raise ClosureError(
                        "BASELINE_PRECONDITION_FAILED", "primary value differs from approved baseline"
                    )
            protected = {}
            for check in self._profile(meta["target_id"])["checks"]:
                if check["kind"] == "invariant":
                    status, raw = client.get(check["probe"]["path"])
                    if status != 200:
                        raise ClosureError("PROTECTED_RESOURCE_UNAVAILABLE", check["id"])
                    protected[check["id"]] = self.store.put(raw)
        manifest = self.store.put(
            canonical({"artifact_hash": contract["baseline_hash"], "protected": protected})
        )
        self._append("verifier", tx, "BASELINED", refs=[manifest])
        return self.status(tx)

    def _evaluator(self, meta):
        return evaluator.load(
            self.store, meta["contract"]["evaluator_hash"], self._profile(meta["target_id"])
        )

    def _probe(self, check, meta, binding, client, bundle):
        probe = check["probe"]
        contract = meta["contract"]
        try:
            if probe["type"] == "active-artifact":
                raw = canonical(client.state())
                active = strict_loads(raw)["artifact_hash"]
                if active == binding["artifact_hash"]:
                    return "PASS", raw
                return ("NOT_COMPLETED" if active == contract["baseline_hash"] else "FAIL"), raw
            if probe["type"] == "staged-artifact":
                # Stage: the exact bound artifact is staged intact in custody, whether or not the
                # target accepted it (that is the deployment check's question).
                raw = self.store.get(binding["artifact_hash"])
                return ("PASS" if digest(raw) == binding["artifact_hash"] else "FAIL"), raw
            if probe["type"] == "baseline-custody":
                raw = self.store.get(meta["current_baseline_hash"])
                return ("PASS" if digest(raw) == contract["baseline_hash"] else "FAIL"), raw
            status, raw = client.get(probe["path"])
            if probe["type"] == "http-unchanged":
                expected = self.custody.manifest(meta["transaction_id"])["protected"][check["id"]]
                return ("PASS" if status == 200 and digest(raw) == expected else "FAIL"), raw
            if status != 200:
                return "FAIL", raw
            criterion = bundle["criteria"][check["id"]]
            frozen_check = next(c for c in contract["checks"] if c["id"] == check["id"])
            # Recovery is judged against the value observed before the change; forward runs
            # against the owner's desired value. Never against the actor's artifact.
            wanted = criterion["restore_equals"] if contract["parent_packet_hash"] else criterion["equals"]
            try:
                live = json_pointer(strict_loads(raw), probe["pointer"])
            except ClosureError:
                return "FAIL", raw
            if canonical(live) == canonical(wanted):
                return "PASS", raw
            if (
                frozen_check["allow_not_completed"]
                and not contract["parent_packet_hash"]
                and canonical(live) == canonical(criterion["restore_equals"])
                and client.state()["artifact_hash"] == contract["baseline_hash"]
            ):
                # Independent read-back: the target still runs the baseline and still serves the
                # original value, so the change was not made (rather than made wrongly).
                return "NOT_COMPLETED", raw
            return "FAIL", raw
        except ClosureError as exc:
            return "UNKNOWN", canonical({"probe_error": exc.code})

    def _observe_one(self, verifier, meta, binding, check, nonce, client, bundle):
        observed_at = self.clock.now()
        result, raw = self._probe(check, meta, binding, client, bundle)
        body = {
            "observation_id": "obs-" + secrets.token_hex(12),
            **{k: binding[k] for k in SUBJECT},
            "check_id": check["id"],
            "evaluator_hash": meta["contract"]["evaluator_hash"],
            "policy_hash": POLICY_HASH,
            "nonce": nonce,
            "phase": check["phase"],
            "observed_at": observed_at,
            "result": result,
            "evidence_hash": self.store.put(raw),
            "tamper_detected": False,
        }
        if check["kind"] == "baseline":
            body["artifact_hash"] = meta["contract"]["baseline_hash"]
        self.custody.ingest(meta["transaction_id"], sign(verifier, "observation", body, observed_at))
        return {"check_id": check["id"], "result": result, "observed_at": observed_at}

    def observe(self, tx, *, phase="all"):
        """Verifier: independent read-only probes bound to the authority's challenges.

        Instant checks are observed once; window checks are sampled across the frozen window,
        so this call blocks until the window closes when phase is 'all' or 'window'.
        """
        verifier = self._identity("verifier")
        meta = self._tx(tx)
        if meta["binding"] is None:
            raise ClosureError("RUN_BINDING_REQUIRED", tx)
        bundle = self._evaluator(meta)  # refuses if the enrolled probe profile changed
        profile = bundle["profile"]
        binding = meta["binding"]["payload"]["body"]
        client = self._client(meta["target_id"])
        checks = {c["id"]: c for c in profile["checks"]}
        used = {r["observation"]["payload"]["body"]["nonce"] for r in self.custody.records(tx)}
        pending = [c for c in binding["challenges"] if c["nonce"] not in used]
        results = []
        instants = [c for c in pending if c["phase"] == "instant"] if phase in {"all", "instant"} else []

        def observe_instant(challenge):
            check = checks[challenge["check_id"]]
            results.append(
                self._observe_one(verifier, meta, binding, check, challenge["nonce"], client, bundle)
            )

        if phase in {"all", "window"}:
            window = meta["contract"]["window"]
            start = milliseconds(binding["window_start"])
            by_check = {}
            for challenge in [c for c in pending if c["phase"] == "window"]:
                by_check.setdefault(challenge["check_id"], []).append(challenge["nonce"])
            total = max((len(v) for v in by_check.values()), default=0)
            issued = 2 * window["min_samples"] - 1
            done = issued - total
            # Samples are spread evenly over [start, end - skew/2]; the last lands inside the window.
            span = window["duration_ms"] - window["max_clock_skew_ms"] // 2
            cost = 250  # observed cost of one instant observation, refined as we go
            for index in range(done, issued):
                due = start + (index * span) // (issued - 1)
                # Window samples keep their schedule; instant checks only use genuine slack.
                while instants and self.clock.now_ms() + 2 * cost < due:
                    t0 = self.clock.now_ms()
                    observe_instant(instants.pop(0))
                    cost = max(50, self.clock.now_ms() - t0)
                delay = due - self.clock.now_ms()
                if delay > 0:
                    time.sleep(delay / 1000)
                if self.clock.now_ms() >= start + window["duration_ms"]:
                    # Woken after the window closed: an out-of-window sample would disqualify the
                    # check, and no sample was taken in time. Leave the remaining challenges unused.
                    break
                for check_id, nonces in by_check.items():
                    if nonces:
                        results.append(
                            self._observe_one(
                                verifier, meta, binding, checks[check_id], nonces.pop(0), client, bundle
                            )
                        )
        for challenge in instants:  # instant checks have no window constraint, only freshness
            observe_instant(challenge)
        if phase in {"all", "window"}:
            # Return only once the frozen window has closed, so the authority can close at once.
            remaining = start + window["duration_ms"] - self.clock.now_ms()
            if remaining > 0:
                time.sleep(remaining / 1000)
        return {"transaction_id": tx, "observations": results}

    # ----- broker: write-ahead intent, side effect, reconciliation -------------------------
    def _intent_path(self, intent_id):
        return self.deployment.role_root("broker") / "intents" / (intent_id + ".json")

    def _intents(self, tx):
        folder = self.deployment.role_root("broker") / "intents"
        if not folder.is_dir():
            return []
        found = [read_json(path, "INTENT_UNKNOWN") for path in sorted(folder.glob("intent-*.json"))]
        return [i for i in found if i["transaction_id"] == tx]

    def start_execution(self, tx):
        """Broker: record EXECUTING with the binding the authority issued (custody checks it)."""
        meta = self._tx(tx)
        if meta["binding"] is None:
            if meta["pending_binding"] is None:
                raise ClosureError("RUN_BINDING_REQUIRED", tx)
            self._append("broker", tx, "EXECUTING", binding=meta["pending_binding"])
            return {"transaction_id": tx, "state": "EXECUTING"}
        return {"transaction_id": tx, "state": "EXECUTING"}

    def deploy(self, tx):
        """Broker: precondition-checked, write-ahead deployment of the bound artifact."""
        self.start_execution(tx)
        if self.custody.state(tx) != "EXECUTING" or self._intents(tx):
            raise ClosureError("DEPLOYMENT_ALREADY_ATTEMPTED", tx)
        intent = self.begin_intent(tx)
        return self.execute_intent(intent["intent_id"])

    def begin_intent(self, tx):
        """Broker: verify the precondition and durably record intent BEFORE any side effect."""
        self._identity("broker")
        meta = self._tx(tx)
        if meta["binding"] is None:
            self.start_execution(tx)
            meta = self._tx(tx)
        state = self._client(meta["target_id"]).state()
        intent = {
            "intent_id": "intent-" + secrets.token_hex(12),
            "transaction_id": tx,
            "target_id": meta["target_id"],
            "artifact_hash": meta["artifact_hash"],
            "expected_current": meta["contract"]["baseline_hash"],
            "observed_current": state["artifact_hash"],
            "status": "PENDING",
            "created_at": self.clock.now(),
            "receipt_hash": None,
        }
        create_json(self._intent_path(intent["intent_id"]), intent)
        return intent

    def execute_intent(self, intent_id):
        intent = read_json(self._intent_path(intent_id), "INTENT_UNKNOWN")
        if intent["status"] != "PENDING":
            raise ClosureError("INTENT_NOT_PENDING", intent["status"])
        if intent["observed_current"] != intent["expected_current"]:
            # Never act on a target whose current state differs from the approved precondition.
            return self._finish_intent(intent, "NOT_DEPLOYED")
        client = self._client(intent["target_id"], with_token=True)
        artifact = self.store.get(intent["artifact_hash"])
        try:
            status, _ = client.deploy(artifact, intent["expected_current"], intent_id)
        except ClosureError:
            return self.reconcile_intent(intent_id)
        if status == 412:
            return self._finish_intent(intent, "NOT_DEPLOYED")
        return self.reconcile_intent(intent_id)

    def reconcile_intent(self, intent_id):
        """Resolve a pending intent from independently read target state; never blind-retry."""
        intent = read_json(self._intent_path(intent_id), "INTENT_UNKNOWN")
        if intent["status"] != "PENDING":
            return {
                "intent_id": intent_id,
                "status": intent["status"],
                "receipt_hash": intent["receipt_hash"],
            }
        try:
            current = self._client(intent["target_id"]).state()["artifact_hash"]
        except ClosureError:
            return {"intent_id": intent_id, "status": "PENDING", "reason": "TARGET_UNREACHABLE"}
        if current == intent["artifact_hash"]:
            return self._finish_intent(intent, "EXECUTED")
        if current == intent["expected_current"]:
            return self._finish_intent(intent, "NOT_DEPLOYED")
        return self._finish_intent(intent, "UNKNOWN")

    def reconcile(self):
        """Broker restart path: resolve every pending intent."""
        folder = self.deployment.role_root("broker") / "intents"
        results = []
        for path in sorted(folder.glob("intent-*.json")) if folder.is_dir() else []:
            if read_json(path, "INTENT_UNKNOWN")["status"] == "PENDING":
                results.append(self.reconcile_intent(path.stem))
        return {"reconciled": results}

    def _finish_intent(self, intent, status):
        binding = self._tx(intent["transaction_id"])["binding"]["payload"]["body"]
        now = self.clock.now()
        body = {
            "receipt_id": intent["intent_id"],
            **{k: binding[k] for k in SUBJECT},
            "operation": "deploy",
            "status": status,
            "recorded_at": now,
        }
        receipt = sign(self._identity("broker"), "action-receipt", body, now)
        receipt_hash = self.custody.submit_receipt(intent["transaction_id"], receipt)["receipt_hash"]
        if status != "UNKNOWN":
            self._append("broker", intent["transaction_id"], "VERIFYING", receipt=receipt)
        final = "QUARANTINED" if status == "UNKNOWN" else "COMPLETED"
        replace_json(
            self._intent_path(intent["intent_id"]), dict(intent, status=final, receipt_hash=receipt_hash)
        )
        return {
            "intent_id": intent["intent_id"],
            "status": final,
            "receipt": status,
            "receipt_hash": receipt_hash,
        }

    # ----- single-process orchestration (development and single-host installs) -------------
    def run(self, tx):
        """Bind, deploy, observe across the whole window, close. Requires every role key locally;
        in an isolated deployment the operator API performs the same steps via role services."""
        if self._tx(tx)["binding"] is None and self._tx(tx)["pending_binding"] is None:
            self.bind(tx)
        deployed = self.deploy(tx)
        if deployed.get("receipt") == "UNKNOWN":
            return dict(self.status(tx), deployment=deployed)
        observed = self.observe(tx, phase="all")
        result = self.close(tx)
        if result["state"] == "OBSERVING":
            result = self.close(tx)
        return dict(result, deployment=deployed, observations=len(observed["observations"]))

    # ----- read models ---------------------------------------------------------------------
    @staticmethod
    def _closure_fields(packet):
        if packet is None:
            return {"verdict": None, "reason_codes": [], "checks": {}, "technical_packet_hash": None}
        body = packet["payload"]["body"]
        return {
            "verdict": body["verdict"],
            "reason_codes": body["reason_codes"],
            "checks": body["checks"],
            "technical_packet_hash": digest(packet),
        }

    def contract(self, tx):
        """Read-only: the exact draft contract (and approval, once signed) for owner review."""
        meta = self.custody.tx(tx)
        return contract_view(self.custody, meta)

    def closure(self, tx):
        """CIP envelope with the ledger's authoritative technical packet (never a candidate)."""
        packet = self.custody.technical_packet(tx)
        if packet is None:
            raise ClosureError("CLOSURE_NOT_ADMITTED", tx)
        return {"protocol": "cip.v1", "packet": packet}

    def audit_export(self, from_sequence=1, limit=1000):
        return self.custody.audit_export(from_sequence, limit)

    def evidence(self, evidence_hash):
        return self.custody.evidence_get(evidence_hash)

    def status(self, tx=None):
        if tx is None:
            return self.custody.listing()
        view = self.custody.view(tx)  # one verified ledger snapshot
        meta = self._tx(tx) if hasattr(self, "_tx") else self.custody.tx(tx)
        return {
            "transaction_id": tx,
            "state": view["state"] or "PROPOSED",
            "approved": meta["approval"] is not None,
            "target_id": meta["target_id"],
            "contract_hash": digest(meta["contract"]),
            "artifact_hash": meta["artifact_hash"],
            "baseline_hash": meta["contract"]["baseline_hash"],
            "window_start": meta["binding"]["payload"]["body"]["window_start"] if meta["binding"] else None,
            "packets": list(meta["packets"]),
            "parent_transaction": meta["parent_transaction"],
            "child_transaction": meta["child_transaction"],
            "ledger_head": view["verified_head"],
            "ledger_sequence": view["sequence"],
            **self._closure_fields(view["packet"]),
        }

    def export_bundle(self, tx):
        """Runtime bundle accepted by `closure-engine evaluate-run` for independent recomputation."""
        meta = self._tx(tx)
        if meta["binding"] is None:
            raise ClosureError("RUN_BINDING_REQUIRED", tx)
        return {
            "mode": "runtime",
            "contract": meta["contract"],
            "approval": meta["approval"],
            "binding": meta["binding"],
            "records": self.custody.records(tx),
            "receipts": self.custody.receipts(tx),
        }


def artifact_bytes(path):
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ClosureError("ARTIFACT_MISSING", str(path)) from exc
    return _bounded_bytes(raw)


def contract_view(custody, meta):
    """Everything the owner approves, in readable form: contract plus evaluator criteria."""
    contract = meta["contract"]
    bundle = strict_loads(custody.store.get(contract["evaluator_hash"]))
    return {
        "transaction_id": meta["transaction_id"],
        "contract_hash": digest(contract),
        "contract": contract,
        "evaluator": bundle,
        "approval": meta["approval"],
        "artifact_hash": meta["artifact_hash"],
        "parent_transaction": meta["parent_transaction"],
    }
