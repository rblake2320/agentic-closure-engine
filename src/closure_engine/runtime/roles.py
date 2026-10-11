"""Per-role services and the keyless distributed runtime used by the operator gateway.

A role service holds exactly one role key (its own state root) and reaches custody over RPC.
It exposes only that role's fixed actions. No route accepts an object to sign: callers name a
transaction, and the service signs only what it constructs itself from custody state.
"""

import base64

from ..protocol import ClosureError, digest
from .custody_service import RemoteCustody
from .rpc import ServiceClient, ServiceHandler, ServiceServer

ROLE_ACTIONS = {
    "actor": {"propose": "propose", "recover": "begin_recovery"},
    "owner": {"approve": "approve", "accept": "accept"},
    "authority": {
        "freeze": "freeze",
        "bind": "bind",
        "close": "close",
        "recover-complete": "complete_recovery",
    },
    "verifier": {"baseline": "baseline", "observe": "observe"},
    "broker": {"deploy": "deploy", "start-execution": "start_execution", "reconcile": "reconcile"},
}
PROPOSE_OPTIONS = {
    "duration_ms",
    "min_samples",
    "max_clock_skew_ms",
    "settle_ms",
    "deadline_ms",
    "recovery_deadline_ms",
}
STATUS = {
    "TRANSACTION_UNKNOWN": 404,
    "TRANSACTION_ALREADY_EXISTS": 409,
    "ALREADY_APPROVED": 409,
    "RUN_ALREADY_BOUND": 409,
    "DEPLOYMENT_ALREADY_ATTEMPTED": 409,
    "NOT_CLOSABLE": 409,
    "OBSERVATION_WINDOW_OPEN": 409,
    "STALE_LEDGER_HEAD": 409,
    "SERVICE_UNREACHABLE": 502,
    "TARGET_UNREACHABLE": 502,
}


def propose_args(body):
    required = {"target_id", "transaction_id", "artifact_base64", "intent"}
    if not required <= set(body) <= required | PROPOSE_OPTIONS:
        raise ClosureError("INVALID_REQUEST")
    try:
        artifact = base64.b64decode(body["artifact_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ClosureError("ARTIFACT_ENCODING_INVALID") from exc
    options = {k: body[k] for k in PROPOSE_OPTIONS if k in body}
    if any(type(v) is not int for v in options.values()) or not isinstance(body["intent"], str):
        raise ClosureError("INVALID_REQUEST")
    return body["target_id"], body["transaction_id"], artifact, body["intent"], options


class RoleServer(ServiceServer):
    def __init__(self, address, role, runtime, *, hosts, credentials):
        if role not in ROLE_ACTIONS:
            raise ClosureError("UNKNOWN_ROLE", role)
        runtime._identity(role)  # refuse to start without this role's enrolled key
        self.role = role
        self.runtime = runtime
        super().__init__(address, _RoleHandler, hosts=hosts, credentials=credentials)


class _RoleHandler(ServiceHandler):
    server_version = "ACE-Role/1"

    def do_GET(self):
        if not self.host_ok():
            return self.send_json(403, {"error": "HOST_OR_ORIGIN_REJECTED"})
        if self.path == "/role/v1/health":
            return self.send_json(200, {"service": "ace-role", "role": self.server.role})
        return self.send_json(404, {"error": "ROUTE_NOT_FOUND"})

    def do_POST(self):
        if not self.host_ok():
            return self.send_json(403, {"error": "HOST_OR_ORIGIN_REJECTED"})
        principal = self.principal()
        if principal is None:
            return self.send_json(401, {"error": "UNAUTHORIZED"})
        if "operator" not in principal["roles"]:
            return self.send_json(403, {"error": "ROLE_REQUIRED", "role": "operator"})
        action = self.path.removeprefix("/role/v1/")
        actions = ROLE_ACTIONS[self.server.role]
        if not self.path.startswith("/role/v1/") or action not in actions:
            return self.send_json(404, {"error": "ROUTE_NOT_FOUND"})
        try:
            body = self.json_body()
            with self.server.write_lock:
                result = self._dispatch(action, actions[action], body)
        except ClosureError as exc:
            return self.send_json(STATUS.get(exc.code, 400), {"error": exc.code, "detail": str(exc)[:300]})
        except (OSError, KeyError, TypeError, ValueError) as exc:
            return self.send_json(500, {"error": "ROLE_SERVICE_ERROR", "type": type(exc).__name__})
        return self.send_json(200, result)

    def _dispatch(self, action, method, body):
        runtime = self.server.runtime
        if action == "propose":
            target, tx, artifact, intent, options = propose_args(body)
            return runtime.propose(target, tx, artifact, intent=intent, **options)
        if action == "reconcile":
            if body:
                raise ClosureError("INVALID_REQUEST")
            return runtime.reconcile()
        allowed = {"transaction_id", "phase"} if action == "observe" else {"transaction_id"}
        if set(body) - allowed or not isinstance(body.get("transaction_id"), str):
            raise ClosureError("INVALID_REQUEST")
        if action == "observe":
            phase = body.get("phase", "all")
            if phase not in {"all", "instant", "window"}:
                raise ClosureError("INVALID_REQUEST")
            return runtime.observe(body["transaction_id"], phase=phase)
        return getattr(runtime, method)(body["transaction_id"])


class DistributedRuntime:
    """Keyless facade with the Runtime surface the operator API needs; each step is performed
    by the role service that owns the key. Holds no private keys and signs nothing."""

    def __init__(self, services, custody_url, custody_token):
        missing = set(ROLE_ACTIONS) - set(services)
        if missing:
            raise ClosureError("ROLE_SERVICE_MISSING", ",".join(sorted(missing)))
        self.services = {role: ServiceClient(url, token) for role, (url, token) in services.items()}
        self.custody = RemoteCustody(custody_url, custody_token)

    def _call(self, role, action, body):
        return self.services[role].call("POST", "/role/v1/" + action, body)

    def propose(self, target_id, transaction_id, artifact, *, intent, **options):
        body = {
            "target_id": target_id,
            "transaction_id": transaction_id,
            "artifact_base64": base64.b64encode(artifact).decode(),
            "intent": intent,
            **options,
        }
        return self._call("actor", "propose", body)

    def begin_recovery(self, tx):
        return self._call("actor", "recover", {"transaction_id": tx})

    def approve(self, tx):
        return self._call("owner", "approve", {"transaction_id": tx})

    def accept(self, tx):
        return self._call("owner", "accept", {"transaction_id": tx})

    def freeze(self, tx):
        return self._call("authority", "freeze", {"transaction_id": tx})

    def bind(self, tx):
        return self._call("authority", "bind", {"transaction_id": tx})

    def close(self, tx):
        return self._call("authority", "close", {"transaction_id": tx})

    def complete_recovery(self, tx):
        return self._call("authority", "recover-complete", {"transaction_id": tx})

    def baseline(self, tx):
        return self._call("verifier", "baseline", {"transaction_id": tx})

    def observe(self, tx, phase="all"):
        return self._call("verifier", "observe", {"transaction_id": tx, "phase": phase})

    def deploy(self, tx):
        return self._call("broker", "deploy", {"transaction_id": tx})

    def reconcile(self):
        return self._call("broker", "reconcile", {})

    def checkpoint(self):
        return self.custody.checkpoint()

    def run(self, tx):
        meta = self.custody.tx(tx)
        if meta["binding"] is None and meta["pending_binding"] is None:
            self.bind(tx)
        deployed = self.deploy(tx)
        if deployed.get("receipt") == "UNKNOWN":
            return dict(self.status(tx), deployment=deployed)
        observed = self.observe(tx, "all")
        result = self.close(tx)
        if result["state"] == "OBSERVING":
            result = self.close(tx)
        return dict(result, deployment=deployed, observations=len(observed["observations"]))

    def _closure_fields(self, tx):
        packet = self.custody.technical_packet(tx)
        if packet is None:
            return {"verdict": None, "reason_codes": [], "checks": {}, "technical_packet_hash": None}
        body = packet["payload"]["body"]
        return {
            "verdict": body["verdict"],
            "reason_codes": body["reason_codes"],
            "checks": body["checks"],
            "technical_packet_hash": digest(packet),
        }

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
        summary = self.custody.summary()
        meta = self.custody.tx(tx)
        return {
            "transaction_id": tx,
            "state": summary["transactions"].get(tx, "PROPOSED"),
            "target_id": meta["target_id"],
            "contract_hash": digest(meta["contract"]),
            "artifact_hash": meta["artifact_hash"],
            "baseline_hash": meta["contract"]["baseline_hash"],
            "window_start": meta["binding"]["payload"]["body"]["window_start"] if meta["binding"] else None,
            "packets": list(meta["packets"]),
            "parent_transaction": meta["parent_transaction"],
            "child_transaction": meta["child_transaction"],
            "ledger_head": summary["verified_head"],
            "ledger_sequence": summary["sequence"],
            **self._closure_fields(tx),
        }

    def export_bundle(self, tx):
        meta = self.custody.tx(tx)
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
