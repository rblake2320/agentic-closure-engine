"""Shared HTTP plumbing for ACE services (custody, role services, operator gateway).

Security properties every service gets:
- An explicit allow-list of ``host:port`` names (e.g. ``custody:9000`` in a container network,
  ``127.0.0.1:8782`` on a host). Requests with any other Host or Origin are rejected; there is
  no wildcard and no bypass.
- Bearer credentials stored only as sha256(token) -> {principal, roles}. A credentials
  *directory* is re-read on every request (``<dir>/credentials.json``), so revocation is live
  even when the directory is a read-only bind mount and the file is replaced by atomic rename.
  An unreadable or invalid credentials file denies everyone (fail closed).
- Strict JSON bodies, bounded sizes, no chunked bodies.
"""

import hashlib
import hmac
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit

from ..protocol import MAX_BYTES, ClosureError, strict_loads

READ_TIMEOUT_S = 15


class _RefuseRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = request.build_opener(request.ProxyHandler({}), _RefuseRedirect())


ROLES = {"actor", "owner", "broker", "verifier", "authority", "custodian", "operator", "viewer"}
HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}:[0-9]{1,5}$|^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$")


def validate_credentials(credentials):
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


class CredentialSource:
    """Static credentials (tests, embedding) or a live directory re-read per request."""

    def __init__(self, value=None, directory=None):
        if (value is None) == (directory is None):
            raise ClosureError("API_CREDENTIALS_INVALID")
        self._static = validate_credentials(value) if value is not None else None
        self.directory = Path(directory) if directory is not None else None
        if self.directory is not None:
            self.current()  # fail at startup if the mount is wrong

    def current(self):
        if self._static is not None:
            return self._static
        try:
            raw = (self.directory / "credentials.json").read_bytes()
        except OSError as exc:
            raise ClosureError("API_CREDENTIALS_MISSING", str(self.directory)) from exc
        return validate_credentials(strict_loads(raw))

    def principal(self, token):
        try:
            credentials = self.current()
        except ClosureError:
            return None  # fail closed: nobody is authenticated
        presented = hashlib.sha256(token.encode()).hexdigest()
        for digest_hex, principal in credentials.items():
            if hmac.compare_digest(presented, digest_hex):
                return principal
        return None


def allowed_hosts(names):
    names = list(names)
    if not names or any(not isinstance(n, str) or not HOST.fullmatch(n) for n in names):
        raise ClosureError("ALLOWED_HOSTS_INVALID")
    return frozenset(names)


class ServiceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, hosts, credentials, read_timeout=READ_TIMEOUT_S):
        """``hosts`` lists the exact host:port names clients use. ``None`` is allowed only for a
        loopback bind and then means 127.0.0.1:<port> and localhost:<port>."""
        if hosts is None and address[0] not in {"127.0.0.1", "localhost"}:
            raise ClosureError("ALLOWED_HOSTS_REQUIRED_FOR_NON_LOOPBACK_BIND", address[0])
        self.allowed = allowed_hosts(hosts) if hosts is not None else None
        self.credentials = (
            credentials if isinstance(credentials, CredentialSource) else CredentialSource(credentials)
        )
        self.write_lock = threading.Lock()
        self.read_timeout = read_timeout
        super().__init__(address, handler)
        if self.allowed is None:
            port = self.server_address[1]
            self.allowed = allowed_hosts([f"127.0.0.1:{port}", f"localhost:{port}"])


class ServiceHandler(BaseHTTPRequestHandler):
    server_version = "ACE-Service/1"

    def setup(self):
        # Socket read timeout: a client that stalls mid-headers or mid-body cannot hold a worker.
        self.timeout = self.server.read_timeout
        super().setup()

    def log_message(self, *_):
        return

    def send_json(self, status, value=None, raw=None, content_type="application/json"):
        body = raw if raw is not None else json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def host_ok(self):
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0] not in self.server.allowed:
            return False
        origins = self.headers.get_all("Origin") or []
        if len(origins) > 1:
            return False
        return not origins or origins[0] in {"http://" + h for h in self.server.allowed} | {
            "https://" + h for h in self.server.allowed
        }

    def principal(self):
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1 or not values[0].startswith("Bearer ") or values[0].count(" ") != 1:
            return None
        return self.server.credentials.principal(values[0][7:])

    def raw_body(self, limit=2 * MAX_BYTES):
        if self.headers.get_all("Transfer-Encoding"):
            raise ClosureError("CHUNKED_BODY_REJECTED")
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1:
            raise ClosureError("AMBIGUOUS_CONTENT_LENGTH")
        if not lengths:
            if self.command == "POST":
                raise ClosureError("CONTENT_LENGTH_REQUIRED")
            return b""
        value = lengths[0].strip()
        if not value.isdigit():
            raise ClosureError("INVALID_LENGTH")
        length = int(value)
        if length > limit:
            raise ClosureError("INPUT_TOO_LARGE")
        chunks, remaining = [], length
        try:
            while remaining:
                chunk = self.rfile.read(remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except (TimeoutError, OSError) as exc:
            self.close_connection = True
            raise ClosureError("BODY_READ_TIMEOUT") from exc
        if remaining:
            self.close_connection = True
            raise ClosureError("TRUNCATED_BODY")
        return b"".join(chunks)

    def json_body(self):
        raw = self.raw_body()
        if not raw:
            return {}
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            raise ClosureError("JSON_CONTENT_TYPE_REQUIRED")
        value = strict_loads(raw)
        if not isinstance(value, dict):
            raise ClosureError("JSON_OBJECT_REQUIRED")
        return value


class ServiceClient:
    """Authenticated client for one ACE service. Errors come back as the service's ClosureError."""

    def __init__(self, base_url, token, *, timeout=120):
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.path not in {"", "/"}:
            raise ClosureError("INVALID_SERVICE_URL", base_url)
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def call(self, method, path, value=None, raw=None, expect="json"):
        headers = {"Authorization": "Bearer " + self.token}
        data = None
        if value is not None:
            data = json.dumps(value).encode()
            headers["Content-Type"] = "application/json"
        elif raw is not None:
            data = raw
            headers["Content-Type"] = "application/octet-stream"
        req = request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            # Same opener as targets: no environment proxies, never follow a redirect, so the
            # bearer token only ever goes to the configured service origin.
            with _OPENER.open(req, timeout=self.timeout) as response:
                body = response.read(2 * MAX_BYTES + 1)
        except error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ClosureError("SERVICE_REDIRECT_REFUSED", f"{self.base}{path}: {exc.code}") from exc
            body = exc.read(4096)
            try:
                code = json.loads(body).get("error", "SERVICE_ERROR")
                detail = json.loads(body).get("detail", "")
            except ValueError:
                code, detail = "SERVICE_ERROR", str(exc.code)
            raise ClosureError(code, detail) from exc
        except (error.URLError, OSError, TimeoutError) as exc:
            raise ClosureError("SERVICE_UNREACHABLE", f"{self.base}{path}: {type(exc).__name__}") from exc
        return body if expect == "bytes" else strict_loads(body)
