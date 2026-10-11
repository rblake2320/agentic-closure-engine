"""Shipped failure matrix: non-deployment, interruption/reconcile and origin pinning, each on
real local HTTP servers owned by the test. Outcomes are written to ACE_FAILURE_MATRIX_OUT when
set, so the receipt is the observed result of this exact run."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from test_runtime_e2e import CHECKS, WINDOW, artifact, expect_of, free_port

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
from closure_engine.runtime.target import TargetClient

RESULTS = {}


@pytest.fixture(scope="module", autouse=True)
def receipt():
    yield
    out = os.environ.get("ACE_FAILURE_MATRIX_OUT")
    if out:
        with open(out, "w", encoding="utf-8") as stream:
            json.dump(RESULTS, stream, indent=2, sort_keys=True)


class Recorder(ThreadingHTTPServer):
    """A different origin that must never be contacted."""

    daemon_threads = True

    def __init__(self):
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def _any(self):
                outer.seen.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                    }
                )
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_PUT = do_POST = _any

        super().__init__(("127.0.0.1", 0), Handler)


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def setup_world(tmp, *, target_cls=ReferenceTargetServer):
    deployment = Deployment(tmp / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-fm")
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    port = free_port()
    target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{port}", CHECKS)
    ReferenceTarget.initialize(tmp / "target", artifact(1), target["deploy_token_sha256"])
    server = serve(target_cls(("127.0.0.1", port), tmp / "target"))
    return deployment, pin, server, port


def prepared(runtime, tx, raw, expect):
    runtime.propose("shop/api", tx, raw, intent="matrix " + tx, expect=expect, **WINDOW)
    for step in ("approve", "freeze", "baseline", "bind"):
        getattr(runtime, step)(tx)


def finish(runtime, tx):
    runtime.observe(tx, phase="all")
    result = runtime.close(tx)
    return runtime.close(tx) if result["state"] == "OBSERVING" else result


def record(name, **facts):
    RESULTS[name] = facts


@pytest.fixture
def world(tmp_path):
    deployment, pin, server, port = setup_world(tmp_path)
    yield deployment, pin, tmp_path, port
    server.shutdown()
    server.server_close()


# ----- confirmed non-deployment ------------------------------------------------------------
def test_target_refuses_artifact_confirmed_not_deployed(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    invalid = json.dumps({"routes": {}}).encode()  # the reference target rejects it (400)
    prepared(runtime, "m-refused", invalid, {"primary": 2})
    deployed = runtime.deploy("m-refused")
    client = TargetClient(deployment.target("shop/api"))
    assert deployed["receipt"] == "NOT_DEPLOYED"
    assert client.state()["artifact_hash"] == digest(artifact(1))  # baseline unchanged
    result = finish(runtime, "m-refused")
    checks = result["checks"]
    record(
        "confirmed_not_deployed_target_refused",
        receipt=deployed["receipt"],
        target_unchanged=True,
        verdict=result["verdict"],
        reason_codes=result["reason_codes"],
        checks=checks,
    )
    assert checks["deployment"] == "NOT_COMPLETED" and checks["stage"] == "PASS"
    assert checks["protected-config"] == "PASS" and checks["protected-other"] == "PASS"
    # The owner's desired value is honestly not served, so the primary check fails.
    assert checks["primary"] == "FAIL"


@pytest.mark.xfail(
    strict=True,
    reason="kernel: PARTIALLY_PROVEN needs every mandatory check PASS or "
    "NOT_COMPLETED, and only deployment/stage may be NOT_COMPLETED; an honest primary "
    "probe FAILs when the change was not deployed. Kernel policy decision (root).",
)
def test_confirmed_not_deployed_is_partially_proven_per_contract(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-partial", json.dumps({"routes": {}}).encode(), {"primary": 2})
    runtime.deploy("m-partial")
    assert finish(runtime, "m-partial")["verdict"] == "PARTIALLY_PROVEN"


def test_credential_rejected_is_not_deployed_without_change(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-401", artifact(2), {"primary": 2})
    deployment.target_token_path("shop/api").write_bytes(b"not-the-enrolled-deploy-credential-0123456789")
    deployed = runtime.deploy("m-401")
    client = TargetClient(deployment.target("shop/api"))
    record(
        "deploy_credential_rejected",
        receipt=deployed["receipt"],
        target_unchanged=client.state()["artifact_hash"] == digest(artifact(1)),
    )
    assert deployed["receipt"] == "NOT_DEPLOYED"
    assert client.state()["artifact_hash"] == digest(artifact(1))


def test_precondition_changed_is_not_deployed_and_newer_state_kept(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-race", artifact(4), expect_of(artifact(4)))
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    other = TargetClient(deployment.target("shop/api"), token)
    other.deploy(artifact(9), digest(artifact(1)), "external")
    deployed = runtime.deploy("m-race")
    result = finish(runtime, "m-race")
    record(
        "precondition_changed",
        receipt=deployed["receipt"],
        verdict=result["verdict"],
        newer_state_kept=other.state()["artifact_hash"] == digest(artifact(9)),
        checks=result["checks"],
    )
    assert deployed["receipt"] == "NOT_DEPLOYED" and result["verdict"] == "DISPROVEN"
    assert other.state()["artifact_hash"] == digest(artifact(9))


# ----- interruption and reconcile ----------------------------------------------------------
def test_crash_after_intent_before_side_effect_reconciles_not_deployed(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-pre", artifact(2), {"primary": 2})
    intent = runtime.begin_intent("m-pre")  # durable WAL, then the process dies before PUT
    restarted = Runtime(Deployment(deployment.root), pin)
    resolved = restarted.reconcile()["reconciled"]
    record("crash_before_side_effect", reconciled=resolved)
    assert resolved == [
        {
            "intent_id": intent["intent_id"],
            "status": "COMPLETED",
            "receipt": "NOT_DEPLOYED",
            "receipt_hash": resolved[0]["receipt_hash"],
        }
    ]
    assert TargetClient(deployment.target("shop/api")).state()["artifact_hash"] == digest(artifact(1))


def test_crash_after_side_effect_reconciles_executed_and_proves(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-post", artifact(2), {"primary": 2})
    intent = runtime.begin_intent("m-post")
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    TargetClient(deployment.target("shop/api"), token).deploy(
        artifact(2), intent["expected_current"], intent["intent_id"]
    )
    restarted = Runtime(Deployment(deployment.root), pin)
    resolved = restarted.reconcile()["reconciled"][0]
    result = finish(restarted, "m-post")
    record("crash_after_side_effect", receipt=resolved["receipt"], verdict=result["verdict"])
    assert resolved["receipt"] == "EXECUTED" and result["verdict"] == "PROVEN"


def test_unexpected_third_state_is_quarantined_and_indeterminate(world):
    deployment, pin, _, _ = world
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-third", artifact(2), {"primary": 2})
    intent = runtime.begin_intent("m-third")
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    TargetClient(deployment.target("shop/api"), token).deploy(
        artifact(7), intent["expected_current"], "other"
    )
    resolved = runtime.reconcile_intent(intent["intent_id"])
    result = runtime.close("m-third")
    record(
        "third_state_quarantined",
        reconcile=resolved["status"],
        receipt=resolved["receipt"],
        verdict=result["verdict"],
        state=result["state"],
    )
    assert resolved["status"] == "QUARANTINED" and resolved["receipt"] == "UNKNOWN"
    assert result["verdict"] == "INDETERMINATE" and result["state"] == "RECOVERY_REQUIRED"


def test_target_outage_keeps_intent_pending_until_state_is_readable(tmp_path):
    deployment, pin, server, port = setup_world(tmp_path)
    runtime = Runtime(deployment, pin)
    prepared(runtime, "m-down", artifact(2), {"primary": 2})
    intent = runtime.begin_intent("m-down")
    server.shutdown()
    server.server_close()
    pending = runtime.reconcile_intent(intent["intent_id"])
    assert pending == {"intent_id": intent["intent_id"], "status": "PENDING", "reason": "TARGET_UNREACHABLE"}
    assert runtime.custody.receipts("m-down") == []  # nothing claimed while blind
    revived = serve(ReferenceTargetServer(("127.0.0.1", port), tmp_path / "target"))
    resolved = runtime.reconcile_intent(intent["intent_id"])
    record("target_outage", while_down=pending["status"], after_restart=resolved["receipt"])
    assert resolved["receipt"] == "NOT_DEPLOYED"
    revived.shutdown()
    revived.server_close()


# ----- origin pinning ------------------------------------------------------------------------
def redirecting_target(recorder):
    """Serves the protocol from a real ReferenceTarget, but redirects PUT and app routes."""

    class Server(ReferenceTargetServer):
        def __init__(self, address, state_dir):
            super().__init__(address, state_dir)
            handler = self.RequestHandlerClass
            location = f"http://127.0.0.1:{recorder.server_address[1]}"

            class Redirecting(handler):
                def _redirect(self, code):
                    self.send_response(code)
                    self.send_header("Location", location + self.path)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def do_PUT(self):
                    self._redirect(307)

                def do_GET(self):
                    if self.path.startswith("/ace/"):
                        return handler.do_GET(self)
                    return self._redirect(302)

            self.RequestHandlerClass = Redirecting

    return Server


def test_redirects_never_leave_the_enrolled_origin(tmp_path):
    recorder = serve(Recorder())
    deployment, pin, server, _ = setup_world(tmp_path, target_cls=redirecting_target(recorder))
    runtime = Runtime(deployment, pin)
    with pytest.raises(ClosureError, match="PRIMARY_UNAVAILABLE"):
        runtime.propose("shop/api", "m-redirect", artifact(2), intent="x", expect={"primary": 2}, **WINDOW)
    client = TargetClient(
        deployment.target("shop/api"), deployment.target_token_path("shop/api").read_bytes().decode()
    )
    status, _ = client.deploy(artifact(2), digest(artifact(1)), "probe-redirect")
    assert status == 307
    assert client.get("/answer")[0] == 302
    assert TargetClient(deployment.target("shop/api")).state()["artifact_hash"] == digest(artifact(1))
    record(
        "redirects",
        put_status=status,
        probe_status=302,
        other_origin_requests=len(recorder.seen),
        credential_leaked=any(r["authorization"] for r in recorder.seen),
    )
    assert recorder.seen == []  # neither the credential nor any probe reached another origin
    for s in (server, recorder):
        s.shutdown()
        s.server_close()


def test_environment_proxy_is_ignored(tmp_path, monkeypatch):
    recorder = serve(Recorder())
    deployment, pin, server, _ = setup_world(tmp_path)
    proxy = f"http://127.0.0.1:{recorder.server_address[1]}"
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, proxy)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    token = deployment.target_token_path("shop/api").read_bytes().decode()
    status, _ = TargetClient(deployment.target("shop/api"), token).deploy(
        artifact(2), digest(artifact(1)), "p"
    )
    record("environment_proxy", deploy_status=status, proxy_requests=len(recorder.seen))
    assert status == 200 and recorder.seen == []
    for s in (server, recorder):
        s.shutdown()
        s.server_close()
