"""Operator JSON API (for the UI) over a runtime facade.

``runtime`` is either the single-host ``Runtime`` or the keyless ``DistributedRuntime`` that
drives isolated role services; the routes are identical. Authentication, Host/Origin allow-list
and live credential reload come from rpc.py. Roles gate actions: actor, owner, broker, verifier,
authority, custodian, operator, viewer. No request field can set time, and there is no route
that signs a caller-supplied object or changes evaluator/probe definitions.
"""

import base64
import json
import mimetypes
import re
import time
from pathlib import Path

from ..protocol import MAX_BYTES, ClosureError, strict_loads
from .roles import propose_args
from .rpc import (
    APPROVAL_MODES,
    APPROVER_ROLE,
    AUTHOR_ROLE,
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
AUTHOR_ACTIONS = frozenset({"propose", "recover"})
APPROVER_ACTIONS = frozenset({"approve", "accept"})
STATUS = {
    "APPROVAL_SEPARATION_REQUIRED": 403,
    "TRANSACTION_UNKNOWN": 404,
    "TARGET_NOT_ENROLLED": 404,
    "INTENT_UNKNOWN": 404,
    "ROUTE_NOT_FOUND": 404,
    "METHOD_NOT_ALLOWED": 405,
    "TRANSACTION_ALREADY_EXISTS": 409,
    "ALREADY_APPROVED": 409,
    "RUN_ALREADY_BOUND": 409,
    "DEPLOYMENT_ALREADY_ATTEMPTED": 409,
    "NOT_CLOSABLE": 409,
    "TRANSACTION_TERMINAL": 409,
    "RECOVERY_NOT_REQUIRED": 409,
    "OBSERVATION_NOT_ALLOWED": 409,
    "ARTIFACT_TOO_LARGE": 413,
    "INPUT_TOO_LARGE": 413,
    "OBSERVATION_WINDOW_OPEN": 409,
    "STALE_LEDGER_HEAD": 409,
    "ILLEGAL_TRANSITION": 409,
    "CLOSURE_NOT_ADMITTED": 404,
    "EVIDENCE_MISSING": 404,
    "TARGET_UNREACHABLE": 502,
    "SERVICE_UNREACHABLE": 502,
}
__all__ = ["ROLES", "ApiServer", "check_separation", "load_credentials", "load_credentials_value"]


def check_separation(approval_mode, principal, action):
    """Route-time separation of duties (defence in depth behind credential validation).

    In ``independent`` mode a principal holding ``owner`` may not author (propose, recover) and
    a principal holding ``actor`` may not approve (approve, accept). ``single-operator`` mode
    never refuses here; it only discloses itself through ``/whoami``."""
    if approval_mode != "independent":
        return
    roles = set(principal["roles"])
    if (action in AUTHOR_ACTIONS and APPROVER_ROLE in roles) or (
        action in APPROVER_ACTIONS and AUTHOR_ROLE in roles
    ):
        raise ClosureError(
            "APPROVAL_SEPARATION_REQUIRED", f"{action} is refused for a principal holding actor and owner"
        )


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
        self,
        address,
        runtime,
        credentials,
        static_dir=None,
        *,
        hosts=None,
        read_timeout=READ_TIMEOUT_S,
        approval_mode="single-operator",
    ):
        if approval_mode not in APPROVAL_MODES:
            raise ClosureError("APPROVAL_MODE_INVALID", str(approval_mode))
        self.approval_mode = approval_mode
        self.runtime = runtime
        self.static_dir = Path(static_dir).resolve() if static_dir else None
        if self.static_dir is not None and not self.static_dir.is_dir():
            raise ClosureError("STATIC_DIR_MISSING", str(self.static_dir))
        super().__init__(address, _Handler, hosts=hosts, credentials=credentials, read_timeout=read_timeout)
        try:
            self.credentials.require(approval_mode)  # fail closed before serving a single request
        except ClosureError:
            self.server_close()
            raise


class _Handler(ServiceHandler):
    server_version = "ACE-Runtime-API/1"

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PUT(self):
        self._handle("PUT")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_OPTIONS(self):
        self._handle("OPTIONS")

    def send_json(self, status, value=None, raw=None, content_type="application/json"):
        if status != 405:
            return super().send_json(status, value, raw, content_type)
        body = json.dumps(value, sort_keys=True).encode()
        self.close_connection = True
        self.send_response(status)
        self.send_header("Allow", "GET, POST")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

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
            if STATUS.get(exc.code) == 413:
                self.close_connection = True
            detail = public_detail(exc)
            while detail.startswith(exc.code):
                detail = detail[len(exc.code) :].lstrip(": ")
            value = {"error": exc.code}
            if detail:
                value["detail"] = detail
            self.send_json(STATUS.get(exc.code, 400), value)
            if exc.code == "INPUT_TOO_LARGE":
                self._drain_rejected_upload()
            return
        except (OSError, KeyError, TypeError, ValueError) as exc:
            return self.send_json(500, {"error": "RUNTIME_ERROR", "type": type(exc).__name__})

    def _drain_rejected_upload(self):
        """After sending 413, consume a bounded rejected upload before TCP close.

        Closing with unread upload bytes can reset Windows TCP before the client reads the
        JSON response. Send first (headers-only clients receive 413 immediately), then discard
        at most 4 MiB for 0.5 seconds; never allocate the upload or wait for an absent body.
        Bodies already consumed by strict JSON parsing do not need this transport cleanup.
        """
        value = self.headers.get("Content-Length", "")
        if not value.isdigit() or int(value) <= 2 * MAX_BYTES:
            return
        remaining = min(int(value), 4 * MAX_BYTES)
        deadline = time.monotonic() + 0.5
        self.connection.settimeout(0.1)
        try:
            while remaining and time.monotonic() < deadline:
                chunk = self.rfile.read1(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except (TimeoutError, OSError):
            return

    @staticmethod
    def _existing_legacy_subject(runtime, tx):
        """Only already-stored legacy slash subjects may use the path routing namespace.

        New proposals retain the strict external validator. Dot segments are never routed;
        unknown suffixes are routes, not synthetic transaction IDs. Custody resolves IDs via
        hashed storage keys, so this existence check does not interpret an ID as a file path.
        """
        if any(part in {".", ".."} for part in tx.split("/")):
            raise ClosureError("ROUTE_NOT_FOUND")
        if "/" in tx and not runtime.custody.exists(tx):
            raise ClosureError("ROUTE_NOT_FOUND")

    @staticmethod
    def _require(principal, role):
        if role not in principal["roles"]:
            raise RoleDenied(role)

    def _route(self, method, path, principal):
        runtime = self.server.runtime
        if method == "GET":
            if path == "/api/v1/whoami":
                if self.server.approval_mode == "independent":
                    # Enforced: no credential may hold both actor and owner (rpc.validate_credentials).
                    mode = "independent-approval"
                else:
                    mode = (
                        "single-operator-administration"
                        if {"actor", "owner"} <= set(principal["roles"])
                        else "role-scoped"
                    )
                    # This is disclosure, not a grant or a human-separation certificate.
                return 200, dict(principal, approval_mode=mode)
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
                self._existing_legacy_subject(runtime, match.group(1))
                return 200, runtime.contract(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/closure", path)
            if match:
                self._existing_legacy_subject(runtime, match.group(1))
                return 200, runtime.closure(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX + r"/bundle", path)
            if match:
                self._existing_legacy_subject(runtime, match.group(1))
                return 200, runtime.export_bundle(match.group(1))
            match = re.fullmatch(r"/api/v1/transactions/" + TX, path)
            if match:
                self._existing_legacy_subject(runtime, match.group(1))
                return 200, runtime.status(match.group(1))
            raise ClosureError("ROUTE_NOT_FOUND")
        if method != "POST":
            raise ClosureError("METHOD_NOT_ALLOWED")
        body = self.json_body()
        with self.server.write_lock:
            if path == "/api/v1/transactions":
                self._require(principal, "actor")
                check_separation(self.server.approval_mode, principal, "propose")
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
            check_separation(self.server.approval_mode, principal, match.group(2))
            self._existing_legacy_subject(runtime, match.group(1))
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
