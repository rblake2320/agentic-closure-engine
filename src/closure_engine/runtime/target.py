"""ACE HTTP target protocol v1: bounded client plus a shipped, persistent reference target.

Protocol (any service can implement it):
  GET  /ace/v1/state     -> {"artifact_hash": "sha256:...", "generation": n}
  GET  /ace/v1/artifact  -> exact active artifact bytes
  PUT  /ace/v1/artifact  -> Authorization: Bearer <deploy token>; If-Match: <expected current
                            artifact_hash>; X-ACE-Intent: <intent id>; body = new artifact bytes.
                            412 when the current artifact differs (no change made).
Application probes are ordinary GETs on enrolled paths. No shell execution anywhere.

The reference target serves a JSON artifact {"routes": {"/path": <json>, ...}} and answers each
route with its JSON. It persists the active artifact atomically and survives restart.
"""

import hashlib
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request

from ..protocol import MAX_BYTES, ClosureError, digest, strict_loads

STATE_PATH = "/ace/v1/state"
ARTIFACT_PATH = "/ace/v1/artifact"


def json_pointer(document, pointer):
    """RFC 6901 lookup; raises ClosureError when the pointer does not resolve."""
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ClosureError("INVALID_JSON_POINTER", pointer)
    value = document
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            raise ClosureError("JSON_POINTER_UNRESOLVED", pointer)
    return value


class TargetClient:
    """Client for one enrolled target. Only the profile's base URL is ever contacted."""

    def __init__(self, profile, token=None):
        self.base = profile["base_url"]
        self.timeout = profile["timeout_ms"] / 1000
        self._token = token

    def _call(self, method, path, body=None, headers=None):
        req = request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read(MAX_BYTES + 1)
                status = response.status
        except error.HTTPError as exc:
            raw, status = exc.read(MAX_BYTES + 1), exc.code
        except (error.URLError, OSError, TimeoutError) as exc:
            raise ClosureError("TARGET_UNREACHABLE", f"{method} {path}: {type(exc).__name__}") from exc
        if len(raw) > MAX_BYTES:
            raise ClosureError("TARGET_RESPONSE_TOO_LARGE", path)
        return status, raw

    def get(self, path):
        return self._call("GET", path)

    def state(self):
        status, raw = self.get(STATE_PATH)
        if status != 200:
            raise ClosureError("TARGET_STATE_UNAVAILABLE", str(status))
        state = strict_loads(raw)
        if not isinstance(state, dict) or set(state) != {"artifact_hash", "generation"}:
            raise ClosureError("TARGET_STATE_INVALID")
        return state

    def artifact(self):
        status, raw = self.get(ARTIFACT_PATH)
        if status != 200:
            raise ClosureError("TARGET_ARTIFACT_UNAVAILABLE", str(status))
        return raw

    def deploy(self, artifact, expected_current, intent_id):
        if self._token is None:
            raise ClosureError("DEPLOY_CREDENTIAL_MISSING")
        headers = {
            "Authorization": "Bearer " + self._token,
            "If-Match": expected_current,
            "X-ACE-Intent": intent_id,
            "Content-Type": "application/octet-stream",
        }
        return self._call("PUT", ARTIFACT_PATH, artifact, headers)


def validate_reference_artifact(raw):
    document = strict_loads(raw)
    routes = document.get("routes") if isinstance(document, dict) else None
    if set(document) != {"routes"} or not isinstance(routes, dict) or not routes:
        raise ClosureError("INVALID_REFERENCE_ARTIFACT")
    if any(not isinstance(p, str) or not p.startswith("/") or p.startswith("/ace/") for p in routes):
        raise ClosureError("INVALID_REFERENCE_ARTIFACT")
    return document


class ReferenceTarget:
    """Persistent state for the reference target (active artifact + generation)."""

    def __init__(self, state_dir):
        self.dir = Path(state_dir)
        self._lock = threading.Lock()
        meta = self.dir / "state.json"
        if not meta.is_file():
            raise ClosureError("TARGET_STATE_MISSING", str(self.dir))
        self.meta = json.loads(meta.read_bytes())
        self.raw = (self.dir / "active.bin").read_bytes()
        if digest(self.raw) != self.meta["artifact_hash"]:
            raise ClosureError("TARGET_STATE_CORRUPT", str(self.dir))
        self.document = validate_reference_artifact(self.raw)

    @staticmethod
    def initialize(state_dir, artifact, token_sha256):
        validate_reference_artifact(artifact)
        if not isinstance(token_sha256, str) or len(token_sha256) != 64:
            raise ClosureError("INVALID_TOKEN_HASH")
        root = Path(state_dir)
        if (root / "state.json").exists():
            raise ClosureError("STATE_ALREADY_EXISTS", str(root))
        root.mkdir(parents=True, exist_ok=True)
        _atomic(root / "active.bin", artifact)
        meta = {"artifact_hash": digest(artifact), "generation": 1, "token_sha256": token_sha256}
        _atomic(root / "state.json", json.dumps(meta, sort_keys=True).encode())
        return {"artifact_hash": meta["artifact_hash"], "generation": 1}

    def state(self):
        return {"artifact_hash": self.meta["artifact_hash"], "generation": self.meta["generation"]}

    def authorized(self, token):
        presented = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(presented, self.meta["token_sha256"])

    def replace(self, expected, artifact):
        with self._lock:
            if expected != self.meta["artifact_hash"]:
                return 412
            document = validate_reference_artifact(artifact)
            _atomic(self.dir / "active.bin", artifact)
            meta = dict(self.meta, artifact_hash=digest(artifact), generation=self.meta["generation"] + 1)
            _atomic(self.dir / "state.json", json.dumps(meta, sort_keys=True).encode())
            self.meta, self.raw, self.document = meta, artifact, document
            return 200


def _atomic(path, raw):
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


class _Handler(BaseHTTPRequestHandler):
    server_version = "ACE-Reference-Target/1"

    def log_message(self, *_):
        return

    def _send(self, status, raw, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        target = self.server.target
        if self.path == STATE_PATH:
            return self._send(200, json.dumps(target.state(), sort_keys=True).encode())
        if self.path == ARTIFACT_PATH:
            return self._send(200, target.raw, "application/octet-stream")
        routes = target.document["routes"]
        if self.path in routes:
            return self._send(200, json.dumps(routes[self.path], sort_keys=True).encode())
        return self._send(404, b'{"error":"NOT_FOUND"}')

    def do_PUT(self):
        target = self.server.target
        if self.path != ARTIFACT_PATH:
            return self._send(404, b'{"error":"NOT_FOUND"}')
        auth = self.headers.get_all("Authorization") or []
        if len(auth) != 1 or not auth[0].startswith("Bearer ") or not target.authorized(auth[0][7:]):
            return self._send(401, b'{"error":"UNAUTHORIZED"}')
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BYTES or self.headers.get("Transfer-Encoding"):
            return self._send(400, b'{"error":"INVALID_LENGTH"}')
        body = self.rfile.read(length)
        try:
            status = target.replace(self.headers.get("If-Match", ""), body)
        except ClosureError as exc:
            return self._send(400, json.dumps({"error": exc.code}).encode())
        if status == 412:
            return self._send(412, json.dumps({"error": "PRECONDITION_FAILED", **target.state()}).encode())
        return self._send(200, json.dumps(target.state(), sort_keys=True).encode())


class ReferenceTargetServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, state_dir):
        self.target = ReferenceTarget(state_dir)
        super().__init__(address, _Handler)
