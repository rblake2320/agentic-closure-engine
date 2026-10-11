"""Authenticated loopback JSON API over the operating runtime (for the operator UI).

Authentication: ``Authorization: Bearer <token>``. Credentials live in a JSON file mapping
``sha256(token)`` hex -> {"principal": name, "roles": [...]} (tokens are never stored).
Roles gate actions: actor, owner, broker, verifier, authority, custodian, operator, viewer.
Every timestamp comes from the server clock; no request field can set time.
The server binds loopback only, rejects foreign Host/Origin headers (DNS rebinding) and
serialises state-changing calls. Optional same-origin static files serve the UI.
"""

import base64
import hashlib
import hmac
import json
import mimetypes
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..protocol import MAX_BYTES, ClosureError, strict_loads

ROLES = {"actor", "owner", "broker", "verifier", "authority", "custodian", "operator", "viewer"}
TX = r"([A-Za-z0-9._:-]+(?:/[A-Za-z0-9._:-]+)*)"
ACTIONS = {
    # action: (required role, facade method)
    "approve": ("owner", "approve"),
    "accept": ("owner", "accept"),
    "freeze": ("authority", "freeze"),
    "bind": ("authority", "bind"),
    "close": ("authority", "close"),
    "recover-complete": ("authority", "complete_recovery"),
    "baseline": ("verifier", "baseline"),
    "observe": ("verifier", "observe"),
    "deploy": ("broker", "deploy"),
    "run": ("operator", "run"),
    "recover": ("actor", "begin_recovery"),
}
PROPOSE_FIELDS = {
    "target_id",
    "transaction_id",
    "artifact_base64",
    "intent",
    "duration_ms",
    "min_samples",
    "max_clock_skew_ms",
    "settle_ms",
    "deadline_ms",
    "recovery_deadline_ms",
}
STATUS = {
    "TRANSACTION_UNKNOWN": 404,
    "TARGET_NOT_ENROLLED": 404,
    "INTENT_UNKNOWN": 404,
    "TRANSACTION_ALREADY_EXISTS": 409,
    "ALREADY_APPROVED": 409,
    "RUN_ALREADY_BOUND": 409,
    "DEPLOYMENT_ALREADY_ATTEMPTED": 409,
    "NOT_CLOSABLE": 409,
    "OBSERVATION_WINDOW_OPEN": 409,
    "STALE_LEDGER_HEAD": 409,
    "ILLEGAL_TRANSITION": 409,
    "TARGET_UNREACHABLE": 502,
}


def load_credentials(path):
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError as exc:
        raise ClosureError("API_CREDENTIALS_MISSING", str(path)) from exc
    return load_credentials_value(strict_loads(raw))


def load_credentials_value(credentials):
    if not isinstance(credentials, dict) or not credentials:
        raise ClosureError("API_CREDENTIALS_INVALID")
    for digest_hex, principal in credentials.items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest_hex) or not isinstance(principal, dict):
            raise ClosureError("API_CREDENTIALS_INVALID")
        if set(principal) != {"principal", "roles"} or not isinstance(principal["principal"], str):
            raise ClosureError("API_CREDENTIALS_INVALID")
        roles = principal["roles"]
        if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
            raise ClosureError("API_CREDENTIALS_INVALID")
    return credentials


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, runtime, credentials, static_dir=None, allow_network=False):
        if address[0] not in {"127.0.0.1", "localhost"} and not allow_network:
            raise ClosureError("API_LOOPBACK_ONLY", address[0])
        self.runtime = runtime
        self.credentials = credentials
        self.static_dir = Path(static_dir).resolve() if static_dir else None
        if self.static_dir is not None and not self.static_dir.is_dir():
            raise ClosureError("STATIC_DIR_MISSING", str(self.static_dir))
        self.write_lock = threading.Lock()
        super().__init__(address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    server_version = "ACE-Runtime-API/1"

    def log_message(self, *_):
        return

    # ----- plumbing ------------------------------------------------------------------------
    def _send(self, status, value=None, raw=None, content_type="application/json"):
        body = raw if raw is not None else json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _origin_ok(self):
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0] not in allowed:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {"http://" + h for h in allowed}

    def _principal(self):
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1 or not values[0].startswith("Bearer ") or values[0].count(" ") != 1:
            return None
        presented = hashlib.sha256(values[0][7:].encode()).hexdigest()
        for digest_hex, principal in self.server.credentials.items():
            if hmac.compare_digest(presented, digest_hex):
                return principal
        return None

    def _body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ClosureError("CHUNKED_BODY_REJECTED")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ClosureError("INVALID_LENGTH") from exc
        if length < 0 or length > 2 * MAX_BYTES:
            raise ClosureError("INPUT_TOO_LARGE")
        if length == 0:
            return {}
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            raise ClosureError("JSON_CONTENT_TYPE_REQUIRED")
        value = strict_loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ClosureError("JSON_OBJECT_REQUIRED")
        return value

    def _require(self, principal, role):
        if role not in principal["roles"]:
            raise PermissionError(role)

    # ----- routing -------------------------------------------------------------------------
    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        if not self._origin_ok():
            return self._send(403, {"error": "HOST_OR_ORIGIN_REJECTED"})
        path = self.path.split("?", 1)[0]
        if method == "GET" and path == "/api/v1/health":
            return self._send(200, {"service": "ace-runtime", "status": "ok"})
        if not path.startswith("/api/"):
            return self._static(method, path)
        principal = self._principal()
        if principal is None:
            return self._send(401, {"error": "UNAUTHORIZED"})
        try:
            status, value = self._route(method, path, principal)
            return self._send(status, value)
        except PermissionError as exc:
            return self._send(403, {"error": "ROLE_REQUIRED", "role": str(exc)})
        except ClosureError as exc:
            return self._send(STATUS.get(exc.code, 400), {"error": exc.code, "detail": str(exc)[:300]})
        except (OSError, KeyError, TypeError, ValueError) as exc:
            return self._send(500, {"error": "RUNTIME_ERROR", "type": type(exc).__name__})

    def _route(self, method, path, principal):
        runtime = self.server.runtime
        if method == "GET":
            if path == "/api/v1/whoami":
                return 200, principal
            if path == "/api/v1/status":
                return 200, runtime.status()
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/bundle", path)
            if match:
                return 200, runtime.export_bundle(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX, path)
            if match:
                return 200, runtime.status(match.group(1))
            raise ClosureError("ROUTE_NOT_FOUND")
        if method != "POST":
            raise ClosureError("METHOD_NOT_ALLOWED")
        body = self._body()
        with self.server.write_lock:
            if path == "/api/v1/transactions":
                self._require(principal, "actor")
                return 201, self._propose(runtime, body)
            if path == "/api/v1/reconcile":
                self._require(principal, "broker")
                return 200, runtime.reconcile()
            if path == "/api/v1/checkpoint":
                self._require(principal, "custodian")
                return 200, runtime.checkpoint()
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/([a-z-]+)", path)
            if not match or match.group(2) not in ACTIONS:
                raise ClosureError("ROUTE_NOT_FOUND")
            role, method_name = ACTIONS[match.group(2)]
            self._require(principal, role)
            if match.group(2) == "observe":
                phase = body.get("phase", "all")
                if set(body) - {"phase"} or phase not in {"all", "instant", "window"}:
                    raise ClosureError("INVALID_REQUEST")
                return 200, runtime.observe(match.group(1), phase=phase)
            if body:
                raise ClosureError("INVALID_REQUEST", "action takes no body")
            return 200, getattr(runtime, method_name)(match.group(1))

    def _propose(self, runtime, body):
        if not {"target_id", "transaction_id", "artifact_base64", "intent"} <= set(body) <= PROPOSE_FIELDS:
            raise ClosureError("INVALID_REQUEST")
        try:
            artifact = base64.b64decode(body["artifact_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ClosureError("ARTIFACT_ENCODING_INVALID") from exc
        options = {
            k: body[k]
            for k in PROPOSE_FIELDS - {"target_id", "transaction_id", "artifact_base64", "intent"}
            if k in body
        }
        if any(type(v) is not int for v in options.values()):
            raise ClosureError("INVALID_REQUEST")
        return runtime.propose(
            body["target_id"], body["transaction_id"], artifact, intent=body["intent"], **options
        )

    def _static(self, method, path):
        root = self.server.static_dir
        if method != "GET" or root is None:
            return self._send(404, {"error": "NOT_FOUND"})
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        candidate = (root / relative).resolve()
        if root not in candidate.parents and candidate != root or not candidate.is_file():
            return self._send(404, {"error": "NOT_FOUND"})
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        return self._send(200, raw=candidate.read_bytes(), content_type=content_type)
