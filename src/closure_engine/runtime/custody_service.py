"""Custody as a protected service, and the client other roles use to reach it.

The custody process holds only the custodian key and the custody state root. Callers are
authenticated per request and each RPC has a fixed caller allow-list. Callers can submit only
objects signed by their own enrolled role; custody validates everything (see custody.py).
"""

from urllib.parse import parse_qs, urlsplit

from ..crypto import verify
from ..protocol import ClosureError, digest
from .custody import LocalCustody
from .rpc import RoleDenied, ServiceClient, ServiceHandler, ServiceServer, public_detail

READERS = {"actor", "owner", "broker", "verifier", "authority", "operator", "viewer"}
EVENT_SIGNERS = {"owner", "broker", "verifier", "authority"}
STATUS = {
    "TRANSACTION_UNKNOWN": 404,
    "EVIDENCE_MISSING": 404,
    "STALE_LEDGER_HEAD": 409,
    "TRANSACTION_ALREADY_EXISTS": 409,
    "ALREADY_APPROVED": 409,
    "RUN_ALREADY_BOUND": 409,
}


class CustodyServer(ServiceServer):
    def __init__(self, address, custody, *, hosts, credentials):
        self.custody = custody
        super().__init__(address, _CustodyHandler, hosts=hosts, credentials=credentials)


class _CustodyHandler(ServiceHandler):
    server_version = "ACE-Custody/1"

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        if not self.host_ok():
            return self.send_json(403, {"error": "HOST_OR_ORIGIN_REJECTED"})
        principal = self.principal()
        if principal is None:
            return self.send_json(401, {"error": "UNAUTHORIZED"})
        roles = set(principal["roles"])
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query, strict_parsing=False).items() if len(v) == 1}
        try:
            result = self._route(method, parts.path, query, roles)
        except RoleDenied as exc:
            return self.send_json(403, {"error": "ROLE_REQUIRED", "role": exc.role})
        except ClosureError as exc:
            return self.send_json(
                STATUS.get(exc.code, 400), {"error": exc.code, "detail": public_detail(exc)}
            )
        except (OSError, KeyError, TypeError, ValueError) as exc:
            return self.send_json(500, {"error": "CUSTODY_ERROR", "type": type(exc).__name__})
        if isinstance(result, bytes):
            return self.send_json(200, raw=result, content_type="application/octet-stream")
        return self.send_json(200, result)

    @staticmethod
    def _need(roles, allowed):
        if not roles & allowed:
            raise RoleDenied(sorted(allowed)[0])

    def _route(self, method, path, query, roles):
        custody = self.server.custody
        tx = query.get("tx")
        if method == "GET":
            self._need(roles, READERS)
            if path == "/custody/v1/position":
                head, sequence = custody.position()
                return {"head": head, "sequence": sequence}
            if path == "/custody/v1/summary":
                return custody.summary()
            if path == "/custody/v1/listing":
                return custody.listing()
            if path == "/custody/v1/evidence" and "hash" in query:
                return custody.evidence_get(query["hash"])
            if path == "/custody/v1/witness-record" and "hash" in query:
                return custody.witness_record(query["hash"])
            if path == "/custody/v1/audit-export":
                try:
                    start = int(query.get("from", "1"))
                    limit = int(query.get("limit", "1000"))
                except ValueError as exc:
                    raise ClosureError("INVALID_EXPORT_RANGE") from exc
                return custody.audit_export(start, limit)
            if tx is None:
                raise ClosureError("ROUTE_NOT_FOUND")
            if path == "/custody/v1/transaction":
                return custody.tx(tx)
            if path == "/custody/v1/exists":
                return {"exists": custody.exists(tx)}
            if path == "/custody/v1/state":
                return {"state": custody.state(tx)}
            if path == "/custody/v1/records":
                return {"items": custody.records(tx)}
            if path == "/custody/v1/receipts":
                return {"items": custody.receipts(tx)}
            if path == "/custody/v1/manifest":
                return custody.manifest(tx)
            if path == "/custody/v1/view":
                return custody.view(tx)
            if path == "/custody/v1/technical-packet":
                return {"packet": custody.technical_packet(tx)}
            raise ClosureError("ROUTE_NOT_FOUND")
        if method != "POST":
            raise ClosureError("METHOD_NOT_ALLOWED")
        if path == "/custody/v1/evidence":
            self._need(roles, {"actor", "verifier", "authority"})
            return {"hash": custody.evidence_put(self.raw_body())}
        body = self.json_body()
        with self.server.write_lock:
            if path == "/custody/v1/transactions":
                self._need(roles, {"actor"})
                return custody.create_tx(
                    body.get("proposal"), body.get("parent_transaction"), proposed_by=body.get("proposed_by")
                )
            if path == "/custody/v1/approval":
                self._need(roles, {"owner"})
                return custody.set_approval(
                    body["transaction_id"],
                    body["approval"],
                    approved_by=body.get("approved_by"),
                    require_independent=body.get("require_independent", False) is True,
                )
            if path == "/custody/v1/binding":
                self._need(roles, {"authority"})
                return custody.set_binding(body["transaction_id"], body["binding"])
            if path == "/custody/v1/events":
                self._need(roles, EVENT_SIGNERS)
                event = body["event"]
                verify(event, "ledger-event", custody.trust)
                signer = custody.trust.record(event["payload"]["key_id"])["role"]
                if signer not in roles:
                    raise RoleDenied(signer)  # a role submits only its own signed events
                return custody.append(event, body["expected_head"])
            if path == "/custody/v1/observations":
                self._need(roles, {"verifier"})
                return custody.ingest(body["transaction_id"], body["observation"])
            if path == "/custody/v1/receipts":
                self._need(roles, {"broker"})
                return custody.submit_receipt(body["transaction_id"], body["receipt"])
            if path == "/custody/v1/checkpoint":
                self._need(roles, {"operator", "custodian"})
                return custody.checkpoint()
        raise ClosureError("ROUTE_NOT_FOUND")


class RemoteStore:
    """Evidence access through custody; every read is re-hashed locally (custody is not trusted)."""

    def __init__(self, client):
        self.client = client

    def get(self, evidence_hash):
        from urllib.parse import quote

        raw = self.client.call("GET", "/custody/v1/evidence?hash=" + quote(evidence_hash), expect="bytes")
        if digest(raw) != evidence_hash:
            raise ClosureError("EVIDENCE_HASH_MISMATCH")
        return raw

    def put(self, raw):
        result = self.client.call("POST", "/custody/v1/evidence", raw=raw)["hash"]
        if result != digest(raw):
            raise ClosureError("EVIDENCE_HASH_MISMATCH")
        return result


class RemoteCustody:
    """Same interface as LocalCustody, over the custody RPC."""

    def __init__(self, base_url, token):
        self.client = ServiceClient(base_url, token)
        self.store = RemoteStore(self.client)

    def _get(self, path, tx):
        from urllib.parse import quote

        return self.client.call("GET", f"{path}?tx={quote(tx, safe='')}")

    def position(self):
        value = self.client.call("GET", "/custody/v1/position")
        return value["head"], value["sequence"]

    def witness_record(self, event_hash):
        from urllib.parse import quote

        return self.client.call("GET", "/custody/v1/witness-record?hash=" + quote(event_hash, safe=""))

    def summary(self):
        return self.client.call("GET", "/custody/v1/summary")

    def state(self, tx):
        return self._get("/custody/v1/state", tx)["state"]

    def tx(self, tx):
        return self._get("/custody/v1/transaction", tx)

    def exists(self, tx):
        return self._get("/custody/v1/exists", tx)["exists"]

    def records(self, tx):
        return self._get("/custody/v1/records", tx)["items"]

    def receipts(self, tx):
        return self._get("/custody/v1/receipts", tx)["items"]

    def manifest(self, tx):
        return self._get("/custody/v1/manifest", tx)

    def view(self, tx):
        return self._get("/custody/v1/view", tx)

    def listing(self):
        return self.client.call("GET", "/custody/v1/listing")

    def technical_packet(self, tx):
        return self._get("/custody/v1/technical-packet", tx)["packet"]

    def audit_export(self, from_sequence=1, limit=1000):
        return self.client.call(
            "GET", f"/custody/v1/audit-export?from={int(from_sequence)}&limit={int(limit)}"
        )

    def evidence_get(self, evidence_hash):
        return self.store.get(evidence_hash)

    def create_tx(self, proposal, parent_transaction=None, *, proposed_by=None):
        return self.client.call(
            "POST",
            "/custody/v1/transactions",
            {"proposal": proposal, "parent_transaction": parent_transaction, "proposed_by": proposed_by},
        )

    def set_approval(self, tx, approval, *, approved_by=None, require_independent=False):
        return self.client.call(
            "POST",
            "/custody/v1/approval",
            {
                "transaction_id": tx,
                "approval": approval,
                "approved_by": approved_by,
                "require_independent": require_independent,
            },
        )

    def set_binding(self, tx, binding):
        return self.client.call("POST", "/custody/v1/binding", {"transaction_id": tx, "binding": binding})

    def append(self, event, expected_head):
        return self.client.call(
            "POST", "/custody/v1/events", {"event": event, "expected_head": expected_head}
        )

    def ingest(self, tx, observation):
        return self.client.call(
            "POST", "/custody/v1/observations", {"transaction_id": tx, "observation": observation}
        )

    def submit_receipt(self, tx, receipt):
        return self.client.call("POST", "/custody/v1/receipts", {"transaction_id": tx, "receipt": receipt})

    def checkpoint(self):
        return self.client.call("POST", "/custody/v1/checkpoint", {})


def local_custody(deployment, trust, clock=None):
    return LocalCustody(deployment, trust, clock)
