"""Operator JSON API (for the UI) over a runtime facade.

``runtime`` is either the single-host ``Runtime`` or the keyless ``DistributedRuntime`` that
drives isolated role services; the routes are identical. Authentication, Host/Origin allow-list
and live credential reload come from rpc.py. Roles gate actions: actor, owner, broker, verifier,
authority, custodian, operator, viewer. No request field can set time, and there is no route
that signs a caller-supplied object or changes evaluator/probe definitions.
"""

import base64
import mimetypes
import re
from pathlib import Path

from ..protocol import ClosureError, strict_loads
from .roles import propose_args
from .rpc import (
    READ_TIMEOUT_S,
    ROLES,
    CredentialSource,
    RoleDenied,
    ServiceHandler,
    ServiceServer,
    public_detail,
    validate_credentials,
)

TX = r"([A-Za-z0-9._:-]+(?:/[A-Za-z0-9._:-]+)*)"
ACTIONS = {
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
STATUS = {
    "TRANSACTION_UNKNOWN": 404,
    "TARGET_NOT_ENROLLED": 404,
    "INTENT_UNKNOWN": 404,
    "ROUTE_NOT_FOUND": 404,
    "TRANSACTION_ALREADY_EXISTS": 409,
    "ALREADY_APPROVED": 409,
    "RUN_ALREADY_BOUND": 409,
    "DEPLOYMENT_ALREADY_ATTEMPTED": 409,
    "NOT_CLOSABLE": 409,
    "OBSERVATION_WINDOW_OPEN": 409,
    "STALE_LEDGER_HEAD": 409,
    "ILLEGAL_TRANSITION": 409,
    "CLOSURE_NOT_ADMITTED": 404,
    "EVIDENCE_MISSING": 404,
    "TARGET_UNREACHABLE": 502,
    "SERVICE_UNREACHABLE": 502,
}
__all__ = ["ROLES", "ApiServer", "load_credentials", "load_credentials_value"]


def load_credentials_value(credentials):
    return validate_credentials(credentials)


def load_credentials(path):
    """A credentials directory (live reload; mount it read-only) or a single credentials file."""
    path = Path(path)
    if path.is_dir():
        return CredentialSource(directory=path)
    try:
        return CredentialSource(strict_loads(path.read_bytes()))
    except FileNotFoundError as exc:
        raise ClosureError("API_CREDENTIALS_MISSING", str(path)) from exc


class ApiServer(ServiceServer):
    def __init__(
        self, address, runtime, credentials, static_dir=None, *, hosts=None, read_timeout=READ_TIMEOUT_S
    ):
        self.runtime = runtime
        self.static_dir = Path(static_dir).resolve() if static_dir else None
        if self.static_dir is not None and not self.static_dir.is_dir():
            raise ClosureError("STATIC_DIR_MISSING", str(self.static_dir))
        super().__init__(address, _Handler, hosts=hosts, credentials=credentials, read_timeout=read_timeout)


class _Handler(ServiceHandler):
    server_version = "ACE-Runtime-API/1"

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        if not self.host_ok():
            return self.send_json(403, {"error": "HOST_OR_ORIGIN_REJECTED"})
        path = self.path.split("?", 1)[0]
        if method == "GET" and path == "/api/v1/health":
            return self.send_json(200, {"service": "ace-runtime", "status": "ok"})
        if not path.startswith("/api/"):
            return self._static(method, path)
        principal = self.principal()
        if principal is None:
            return self.send_json(401, {"error": "UNAUTHORIZED"})
        try:
            status, value = self._route(method, path, principal)
            return self.send_json(status, value)
        except RoleDenied as exc:
            return self.send_json(403, {"error": "ROLE_REQUIRED", "role": exc.role})
        except ClosureError as exc:
            return self.send_json(
                STATUS.get(exc.code, 400), {"error": exc.code, "detail": public_detail(exc)}
            )
        except (OSError, KeyError, TypeError, ValueError) as exc:
            return self.send_json(500, {"error": "RUNTIME_ERROR", "type": type(exc).__name__})

    @staticmethod
    def _require(principal, role):
        if role not in principal["roles"]:
            raise RoleDenied(role)

    def _route(self, method, path, principal):
        runtime = self.server.runtime
        if method == "GET":
            if path == "/api/v1/whoami":
                return 200, principal
            if path == "/api/v1/status":
                return 200, runtime.status()
            if path == "/api/v1/audit-export":
                query = dict(
                    part.split("=", 1) for part in self.path.partition("?")[2].split("&") if "=" in part
                )
                try:
                    start, limit = int(query.get("from", "1")), int(query.get("limit", "1000"))
                except ValueError as exc:
                    raise ClosureError("INVALID_EXPORT_RANGE") from exc
                return 200, runtime.audit_export(start, limit)
            match = re.fullmatch(r"/api/v1/evidence/(sha256:[0-9a-f]{64})", path)
            if match:
                return 200, {
                    "hash": match.group(1),
                    "base64": base64.b64encode(runtime.evidence(match.group(1))).decode(),
                }
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/contract", path)
            if match:
                return 200, runtime.contract(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/closure", path)
            if match:
                return 200, runtime.closure(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/bundle", path)
            if match:
                return 200, runtime.export_bundle(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX, path)
            if match:
                return 200, runtime.status(match.group(1))
            raise ClosureError("ROUTE_NOT_FOUND")
        if method != "POST":
            raise ClosureError("METHOD_NOT_ALLOWED")
        body = self.json_body()
        with self.server.write_lock:
            if path == "/api/v1/transactions":
                self._require(principal, "actor")
                target, tx, artifact, intent, options = propose_args(body)
                return 201, runtime.propose(target, tx, artifact, intent=intent, **options)
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

    def _static(self, method, path):
        root = self.server.static_dir
        if method != "GET" or root is None:
            return self.send_json(404, {"error": "NOT_FOUND"})
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        candidate = (root / relative).resolve()
        if (root not in candidate.parents and candidate != root) or not candidate.is_file():
            return self.send_json(404, {"error": "NOT_FOUND"})
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        return self.send_json(200, raw=candidate.read_bytes(), content_type=content_type)
