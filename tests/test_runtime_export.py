"""Closure export and audit-export replay seam over the real API, real target and runtime."""

import base64
import hashlib
import json
import threading

import pytest
from test_runtime_api import RELEASE, TOKENS, VIEWER, call
from test_runtime_e2e import CHECKS, WINDOW, artifact, free_port

from closure_engine.crypto import TrustStore
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
from closure_engine.runtime.export import replay_audit_export


@pytest.fixture
def service(tmp_path):
    """Running API plus the verifier's own copy of the public enrollment and operator pin."""
    deployment = Deployment(tmp_path / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-exp")
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    tport = free_port()
    target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{tport}", CHECKS)
    ReferenceTarget.initialize(tmp_path / "target", artifact(1), target["deploy_token_sha256"])
    tserver = ReferenceTargetServer(("127.0.0.1", tport), tmp_path / "target")
    credentials = {hashlib.sha256(t.encode()).hexdigest(): p for t, p in TOKENS.items()}
    server = ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), credentials)
    for s in (tserver, server):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    verifier_trust = TrustStore.from_dict(json.loads(deployment.trust_path.read_bytes()))
    yield server.server_address[1], verifier_trust, pin
    for s in (server, tserver):
        s.shutdown()
        s.server_close()


def release(port, tx, raw):
    body = {
        "target_id": "shop/api",
        "transaction_id": tx,
        "artifact_base64": base64.b64encode(raw).decode(),
        "expect": {"primary": json.loads(raw)["routes"]["/answer"]["answer"]},
        "intent": "export test",
        **{k: WINDOW[k] for k in ("duration_ms", "min_samples", "settle_ms")},
        "max_clock_skew_ms": WINDOW["max_clock_skew_ms"],
    }
    assert call(port, "POST", "/api/v1/transactions", body, RELEASE)[0] == 201
    for action in ("approve", "freeze", "baseline", "run"):
        status, value = call(port, "POST", f"/api/v1/transactions/{tx}/{action}", None, RELEASE)
        assert status == 200, value
    return value


def pages(port, limit=1000):
    out, start = [], 1
    while True:
        status, page = call(port, "GET", f"/api/v1/audit-export?from={start}&limit={limit}", token=VIEWER)
        assert status == 200, page
        out.append(page)
        if page["next_sequence"] is None:
            return out
        start = page["next_sequence"]


def fetcher(port):
    def fetch(evidence_hash):
        status, value = call(port, "GET", "/api/v1/evidence/" + evidence_hash, token=VIEWER)
        if status != 200:
            raise ClosureError("EVIDENCE_MISSING", evidence_hash)
        return base64.b64decode(value["base64"])

    return fetch


@pytest.fixture
def exported(service):
    port, trust, pin = service
    assert release(port, "exp-1", artifact(5))["verdict"] == "PROVEN"
    return port, trust, pin


def test_closure_endpoint_returns_ledger_admitted_packet_and_status_reports_it(exported):
    port, trust, pin = exported
    status, closure = call(port, "GET", "/api/v1/transactions/exp-1/closure", token=VIEWER)
    assert status == 200 and closure["protocol"] == "cip.v1"
    view = call(port, "GET", "/api/v1/transactions/exp-1", token=VIEWER)[1]
    assert view["verdict"] == "PROVEN" and view["technical_packet_hash"] == digest(closure["packet"])
    assert view["checks"]["primary"] == "PASS" and view["reason_codes"] == []
    assert call(port, "GET", "/api/v1/transactions/nope/closure", token=VIEWER)[0] == 404


def test_audit_export_replays_independently_with_pages_and_prior_anchor(exported):
    port, trust, pin = exported
    first = pages(port)
    anchor = first[-1]["checkpoint"]
    release(port, "exp-2", artifact(6))
    paged = pages(port, limit=3)
    assert len(paged) > 2
    result = replay_audit_export(
        paged, trust, pin, fetcher(port), prior_checkpoint=anchor, transaction="exp-2"
    )
    assert result["closure"]["verdict"] == "PROVEN"
    assert result["closure"]["packet_hash"] == digest(
        call(port, "GET", "/api/v1/transactions/exp-2/closure", token=VIEWER)[1]["packet"]
    )
    assert result["transactions"]["exp-1"] == "PROVEN"


def test_tampered_export_or_evidence_is_rejected(exported):
    port, trust, pin = exported
    export = pages(port)
    with pytest.raises(ClosureError, match="TRUST_ANCHOR_MISMATCH"):
        replay_audit_export(export, trust, "sha256:" + "0" * 64, fetcher(port))
    dropped = json.loads(json.dumps(export))
    dropped[0]["events"].pop()  # truncated history no longer matches the signed checkpoint
    with pytest.raises(ClosureError):
        replay_audit_export(dropped, trust, pin, fetcher(port), transaction="exp-1")

    def lying(evidence_hash):
        return b"substituted bytes"

    with pytest.raises(ClosureError, match="EVIDENCE_HASH_MISMATCH"):
        replay_audit_export(export, trust, pin, lying, transaction="exp-1")


def test_export_range_is_bounded(exported):
    port, trust, pin = exported
    assert call(port, "GET", "/api/v1/audit-export?limit=999999", token=VIEWER)[0] == 400
    assert call(port, "GET", "/api/v1/audit-export?from=0", token=VIEWER)[0] == 400
    assert call(port, "GET", "/api/v1/audit-export")[0] == 401
