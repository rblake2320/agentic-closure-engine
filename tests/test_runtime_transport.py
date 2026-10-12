"""Legacy probe compatibility and service transport hardening, on local servers owned by the test."""

import hashlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from test_runtime_e2e import CHECKS, WINDOW, artifact, free_port

from closure_engine.protocol import ClosureError, digest
from closure_engine.runtime import (
    ROLES,
    Deployment,
    ReferenceTarget,
    ReferenceTargetServer,
    Runtime,
    enroll,
    enroll_target,
    init_identity,
)
from closure_engine.runtime.api import ApiServer
from closure_engine.runtime.rpc import ServiceClient

LEGACY = [dict(c, probe={"type": "artifact-bytes"}) if c["kind"] == "stage" else c for c in CHECKS]
TOKEN = "transport-token-0123456789abcdef0123456789"
CREDENTIALS = {hashlib.sha256(TOKEN.encode()).hexdigest(): {"principal": "t", "roles": ["viewer"]}}


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Recorder(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def _any(self):
                outer.seen.append({"path": self.path, "authorization": self.headers.get("Authorization")})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_POST = _any

        super().__init__(("127.0.0.1", 0), Handler)


def redirector(location):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def _redirect(self):
            self.send_response(307)
            self.send_header("Location", location + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST = _redirect

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    return server


# ----- legacy probe semantics ---------------------------------------------------------------
def legacy_world(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-lg")
    pin = enroll(deployment, [c["id"] for c in LEGACY])["trust_hash"]
    port = free_port()
    target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{port}", LEGACY)
    ReferenceTarget.initialize(tmp_path / "target", artifact(1), target["deploy_token_sha256"])
    return deployment, pin, serve(ReferenceTargetServer(("127.0.0.1", port), tmp_path / "target"))


def run_legacy(runtime, tx, raw, expect):
    runtime.propose("shop/api", tx, raw, intent="legacy", expect=expect, **WINDOW)
    for step in ("approve", "freeze", "baseline", "bind", "deploy"):
        getattr(runtime, step)(tx)
    runtime.observe(tx, phase="all")
    result = runtime.close(tx)
    return runtime.close(tx) if result["state"] == "OBSERVING" else result


def test_legacy_served_artifact_probe_still_enrolls_and_reads_back_served_bytes(tmp_path):
    deployment, pin, server = legacy_world(tmp_path)
    runtime = Runtime(deployment, pin)
    proven = run_legacy(runtime, "lg-ok", artifact(2), {"primary": 2})
    assert proven["verdict"] == "PROVEN" and proven["checks"]["stage"] == "PASS"
    refused = run_legacy(runtime, "lg-refused", json.dumps({"routes": {}}).encode(), {"primary": 3})
    # Legacy meaning preserved: the target does not serve the bound artifact -> stage FAIL.
    assert refused["checks"]["stage"] == "FAIL" and refused["verdict"] == "DISPROVEN"
    server.shutdown()
    server.server_close()


# ----- ServiceClient origin pinning -----------------------------------------------------------
def test_service_client_refuses_redirects_and_never_sends_token_elsewhere():
    recorder = serve(Recorder())
    bounce = serve(redirector(f"http://127.0.0.1:{recorder.server_address[1]}"))
    client = ServiceClient(f"http://127.0.0.1:{bounce.server_address[1]}", TOKEN)
    for method, body in (("GET", None), ("POST", {"x": 1})):
        with pytest.raises(ClosureError, match="SERVICE_REDIRECT_REFUSED"):
            client.call(method, "/custody/v1/summary", body)
    assert recorder.seen == []
    for s in (bounce, recorder):
        s.shutdown()
        s.server_close()


def test_service_client_ignores_environment_proxies_and_still_works(monkeypatch, tmp_path):
    recorder = serve(Recorder())
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{recorder.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    api = serve(ApiServer(("127.0.0.1", 0), None, CREDENTIALS))
    client = ServiceClient(f"http://127.0.0.1:{api.server_address[1]}", TOKEN)
    assert client.call("GET", "/api/v1/whoami") == {
        "principal": "t",
        "roles": ["viewer"],
        "approval_mode": "role-scoped",
    }
    assert recorder.seen == []
    for s in (api, recorder):
        s.shutdown()
        s.server_close()


# ----- request body strictness --------------------------------------------------------------
@pytest.fixture
def strict_api():
    server = serve(ApiServer(("127.0.0.1", 0), None, CREDENTIALS, read_timeout=1))
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def raw_request(port, head, body=b"", stall=None):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(head.replace("\n", "\r\n").encode() + b"\r\n" + body)
        if stall:
            time.sleep(stall)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    status = int(data.split(b" ", 2)[1])
    payload = json.loads(data.split(b"\r\n\r\n", 1)[1] or b"{}")
    return status, payload


def head(port, extra):
    return (
        f"POST /api/v1/transactions/x/approve HTTP/1.1\nHost: 127.0.0.1:{port}\n"
        f"Authorization: Bearer {TOKEN}\nContent-Type: application/json\nConnection: close\n{extra}"
    )


def test_duplicate_content_length_is_rejected(strict_api):
    status, body = raw_request(strict_api, head(strict_api, "Content-Length: 2\nContent-Length: 2\n"), b"{}")
    assert (status, body["error"]) == (400, "AMBIGUOUS_CONTENT_LENGTH")


@pytest.mark.parametrize("value", ["+2", "2.0", "-1", "two", " "])
def test_non_numeric_content_length_is_rejected(strict_api, value):
    status, body = raw_request(strict_api, head(strict_api, f"Content-Length: {value}\n"), b"{}")
    assert (status, body["error"]) == (400, "INVALID_LENGTH")


def test_post_without_content_length_is_rejected(strict_api):
    status, body = raw_request(strict_api, head(strict_api, ""))
    assert (status, body["error"]) == (400, "CONTENT_LENGTH_REQUIRED")


def test_chunked_body_is_rejected(strict_api):
    status, body = raw_request(
        strict_api, head(strict_api, "Transfer-Encoding: chunked\n"), b"2\r\n{}\r\n0\r\n\r\n"
    )
    assert (status, body["error"]) == (400, "CHUNKED_BODY_REJECTED")


def test_stalled_truncated_body_times_out_and_server_stays_available(strict_api):
    started = time.monotonic()
    status, body = raw_request(strict_api, head(strict_api, "Content-Length: 100\n"), b'{"a":')
    assert (status, body["error"]) == (400, "BODY_READ_TIMEOUT")
    assert time.monotonic() - started < 8
    healthy = raw_request(
        strict_api, f"GET /api/v1/health HTTP/1.1\nHost: 127.0.0.1:{strict_api}\nConnection: close\n"
    )
    assert healthy[0] == 200
    assert digest(b"x")  # keep import used for clarity of hashing helpers
