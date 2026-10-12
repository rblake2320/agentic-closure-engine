"""Opus independent probes for the owner's live ACE browser reports (baseline main e3d3538).

Each probe drives the real runtime through the real authenticated HTTP API against a real
reference target on loopback, in a disposable temporary deployment. Red probes state the
required behaviour; GREEN CONTROL probes pin defences that already hold and must stay green.
Field names marked PROPOSED (deployment.reason, allowed_actions, bundle trust/checkpoint/events)
are requirements handed to the implementing lanes; rename them here only by agreement.
"""

import base64
import hashlib
import http.client
import json
import threading

import pytest
from test_runtime_e2e import CHECKS, WINDOW, artifact, free_port

from closure_engine.protocol import ClosureError
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

UI_LIMIT = 524288  # web/closure.js refuses artifacts larger than 512 KiB
SIGNERS = ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"]
TOKENS = {
    "viewer-token-0123456789abcdef0123456789": {"principal": "auditor", "roles": ["viewer"]},
    "release-token-0123456789abcdef012345678": {"principal": "release-manager", "roles": SIGNERS},
    "actor-token-0123456789abcdef01234567890": {"principal": "developer", "roles": ["actor"]},
    "owner-token-0123456789abcdef01234567890": {"principal": "product-owner", "roles": ["owner"]},
}
VIEWER, RELEASE, ACTOR, OWNER = list(TOKENS)


class Live:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.deployment = Deployment(tmp_path / "ace")
        for role in ROLES:
            init_identity(self.deployment.role_root(role), role, role + "-live")
        self.pin = enroll(self.deployment, [c["id"] for c in CHECKS])["trust_hash"]
        tport = free_port()
        target = enroll_target(self.deployment, "shop/api", f"http://127.0.0.1:{tport}", CHECKS)
        ReferenceTarget.initialize(tmp_path / "target", artifact(1), target["deploy_token_sha256"])
        self.target = ReferenceTargetServer(("127.0.0.1", tport), tmp_path / "target")
        self.runtime = Runtime(self.deployment, self.pin)
        credentials = {hashlib.sha256(t.encode()).hexdigest(): p for t, p in TOKENS.items()}
        self.server = ApiServer(("127.0.0.1", 0), self.runtime, credentials)
        self.port = self.server.server_address[1]
        for s in (self.target, self.server):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def close(self):
        for s in (self.server, self.target):
            s.shutdown()
            s.server_close()

    def call(self, method, path, body=None, token=RELEASE, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        headers = {"Host": f"127.0.0.1:{self.port}", "Authorization": "Bearer " + token}
        if body is not None:
            raw = json.dumps(body).encode()
        if raw is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        try:
            return response.status, json.loads(data)
        except ValueError:
            return response.status, data

    def propose(self, tx, raw, expect, token=RELEASE):
        body = {
            "target_id": "shop/api",
            "transaction_id": tx,
            "artifact_base64": base64.b64encode(raw).decode(),
            "intent": "live review " + tx,
            "expect": expect,
            **WINDOW,
        }
        return self.call("POST", "/api/v1/transactions", body, token)

    def act(self, tx, action, token=RELEASE, body=None):
        return self.call("POST", f"/api/v1/transactions/{tx}/{action}", body, token)

    def drive(self, tx, raw, expect):
        """Propose, approve, freeze, baseline and run one transaction to a verdict."""
        status, value = self.propose(tx, raw, expect)
        assert status == 201, value
        for action in ("approve", "freeze", "baseline"):
            status, value = self.act(tx, action)
            assert status == 200, (action, value)
        status, value = self.act(tx, "run")
        assert status == 200, value
        return value

    def status(self, tx):
        status, value = self.call("GET", f"/api/v1/transactions/{tx}", token=VIEWER)
        assert status == 200, value
        return value

    def listing_ids(self):
        return {i["transaction_id"] for i in self.call("GET", "/api/v1/status", token=VIEWER)[1]["items"]}


@pytest.fixture
def live(tmp_path):
    world = Live(tmp_path)
    yield world
    world.close()


def refused(status):
    return status in {400, 409, 422}


# ----- R: transaction-id reservation and dot segments -------------------------------------------
def test_r1_user_cannot_reserve_another_transactions_recovery_id(live):
    """Reported: 'catalog-corrected-20261011/recovery' accepted 201. The runtime names every
    recovery child '<parent>/recovery', so a user-chosen id in that namespace pre-empts it."""
    status, value = live.propose("victim/recovery", artifact(5), {"primary": 5})
    assert refused(status), (status, value)  # RED at e3d3538: 201
    assert "victim/recovery" not in live.listing_ids()


def test_r1_harm_reserved_recovery_id_blocks_the_victims_real_recovery(live):
    # The squatter goes first (on the baseline this is accepted); the victim then genuinely fails.
    live.propose("victim/recovery", artifact(5), {"primary": 5}, token=ACTOR)
    result = live.drive("victim", artifact(2), {"primary": 99})  # deploys, serves 2, owner wanted 99
    assert result["verdict"] == "DISPROVEN" and result["state"] == "RECOVERY_REQUIRED", result
    status, value = live.act("victim", "recover")
    assert status == 201 or status == 200, (status, value)  # RED at e3d3538: 409 TRANSACTION_ALREADY_EXISTS
    assert live.status("victim/recovery")["parent_transaction"] == "victim"


@pytest.mark.parametrize("tx", ["adv/../../evil", "a/./b", "..", ".", "a/.."])
def test_r2_dot_segment_ids_are_refused_before_storage(live, tx):
    """Reported: 'adv/../../evil' accepted 201 but unreachable 404 (browsers and curl remove dot
    segments before sending). An id that the product's own URLs cannot address must be refused."""
    stored = sorted(p.name for p in (live.deployment.role_root("custodian")).rglob("*.json"))
    status, value = live.propose(tx, artifact(6), {"primary": 6})
    assert refused(status), (status, value)  # RED at e3d3538: 201
    assert tx not in live.listing_ids()
    assert sorted(p.name for p in (live.deployment.role_root("custodian")).rglob("*.json")) == stored


def test_r2_storage_mapping_is_contained_for_hostile_ids(live):
    """Accurate containment fact (not inferred): ids map to sha256-derived file names, so a
    dot-segment id cannot escape the custody root. Recorded so a fix does not regress it."""
    before = {p for p in live.root.rglob("*") if p.is_file()}
    live.propose("adv/../../evil", artifact(6), {"primary": 6})
    created = {p for p in live.root.rglob("*") if p.is_file()} - before
    custody = live.deployment.role_root("custodian").resolve()
    assert all(custody in p.resolve().parents for p in created), created


# ----- S: artifact size boundary -------------------------------------------------------------------
def test_s1_decoded_boundary_matches_the_ui_limit(live):
    """Reported: 600000/700000-byte artifacts accepted although the UI allows 512 KiB."""
    status, value = live.propose("size-at-limit", b"a" * UI_LIMIT, {"primary": 2})
    assert status == 201, (status, value)  # GREEN at e3d3538: the boundary itself is accepted
    for size in (UI_LIMIT + 1, 600000, 700000):
        status, value = live.propose(f"size-{size}", b"a" * size, {"primary": 2})
        assert status == 413 and isinstance(value, dict) and value.get("error"), (size, status, value)  # RED
        assert f"size-{size}" not in live.listing_ids()


def test_s2_oversized_request_gets_a_typed_response_not_a_disconnect(live):
    """Reported: a 2 MB upload disconnects. The client must receive a JSON 413."""
    raw = json.dumps(
        {
            "target_id": "shop/api",
            "transaction_id": "size-2mb",
            "artifact_base64": base64.b64encode(b"a" * 1_700_000).decode(),
            "intent": "too large",
            "expect": {"primary": 1},
        }
    ).encode()
    assert len(raw) > 2 * 1_048_576
    try:
        status, value = live.call("POST", "/api/v1/transactions", raw=raw)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
        pytest.fail(f"connection dropped instead of a typed refusal: {type(exc).__name__}")  # RED
    assert status == 413 and isinstance(value, dict) and value.get("error"), (status, value)
    assert "size-2mb" not in live.listing_ids()


# ----- T: actions on finished transactions --------------------------------------------------------
def test_t1_terminal_actions_are_refused_409_without_ledger_change(live):
    """Reported: observe and recover-complete on a terminal transaction return 200 with no change."""
    result = live.drive("done", artifact(3), {"primary": 3})
    assert result["verdict"] == "PROVEN", result
    assert live.act("done", "accept")[1]["state"] == "ACCEPTED"
    before = live.status("done")
    answers = {
        action: live.act("done", action, body=body)
        for action, body in (("observe", {"phase": "all"}), ("recover-complete", None))
    }
    for action, (status, value) in answers.items():
        assert status == 409 and value.get("error"), answers  # RED at e3d3538: 200 for both
    after = live.status("done")
    assert (after["state"], after["ledger_head"]) == (before["state"], before["ledger_head"])


# ----- N: NOT_DEPLOYED reason and impossible recovery ----------------------------------------------
def test_n1_not_deployed_reason_is_reported_and_recovery_is_not_offered(live):
    """Reported: the NOT_DEPLOYED reason is absent and the UI offers a recovery that cannot run."""
    refused_artifact = json.dumps({"routes": {}}).encode()  # the reference target answers 400
    result = live.drive("never-deployed", refused_artifact, {"primary": 2})
    assert result["deployment"]["receipt"] == "NOT_DEPLOYED", result
    view = live.status("never-deployed")
    assert view["state"] != "RECOVERY_REQUIRED", view
    # Recovery really is impossible here (nothing was deployed) ...
    status, value = live.act("never-deployed", "recover", token=ACTOR)
    assert status == 409 and value.get("error"), (status, value)  # RED at e3d3538: 400 RECOVERY_NOT_REQUIRED
    # ... so the server, which the UI follows, must say so and say why (PROPOSED fields).
    deployment = view.get("deployment") or {}
    assert deployment.get("receipt") == "NOT_DEPLOYED", view  # RED: status has no receipt
    assert isinstance(deployment.get("reason"), str) and deployment["reason"], view  # RED
    assert isinstance(view.get("allowed_actions"), list), view  # RED
    assert "recover" not in view["allowed_actions"], view


# ----- P: external pinning -----------------------------------------------------------------------
def foreign_trust(tmp_path):
    other = Deployment(tmp_path / "foreign")
    for role in ROLES:
        init_identity(other.role_root(role), role, role + "-foreign")
    pin = enroll(other, [c["id"] for c in CHECKS])["trust_hash"]
    return other.load_trust(pin), pin


def test_p1_green_control_audit_replay_roots_trust_in_the_operator_pin(live):
    result = live.drive("pinned", artifact(4), {"primary": 4})
    assert result["verdict"] == "PROVEN", result
    status, page = live.call("GET", "/api/v1/audit-export", token=VIEWER)
    assert status == 200
    trust = live.deployment.load_trust(live.pin)
    fetch = live.runtime.evidence
    replayed = replay_audit_export([page], trust, live.pin, fetch, transaction="pinned")
    assert replayed["closure"]["verdict"] == "PROVEN"
    attacker, attacker_pin = foreign_trust(live.root)
    with pytest.raises(ClosureError) as wrong_key:
        replay_audit_export([page], attacker, live.pin, fetch)
    assert wrong_key.value.code == "TRUST_ANCHOR_MISMATCH"
    with pytest.raises(ClosureError) as self_pinned:
        replay_audit_export([page], attacker, attacker_pin, fetch)
    assert self_pinned.value.code == "EXPORT_TRUST_MISMATCH"


def test_p2_transaction_export_carries_public_material_checkable_against_an_external_pin(live):
    """Reported: the export lacks the public trust, policy and ledger needed to verify offline.
    Required (PROPOSED shape): the downloaded export carries the public trust snapshot, whose hash
    the verifier compares with an operator-held pin (the bundled key is never the root), plus the
    signed ledger events and custodian checkpoint for the transaction."""
    from closure_engine.crypto import TrustStore

    live.drive("portable", artifact(8), {"primary": 8})
    status, bundle = live.call("GET", "/api/v1/transactions/portable/bundle", token=VIEWER)
    assert status == 200, bundle
    assert isinstance(bundle.get("trust"), dict), sorted(bundle)  # RED at e3d3538
    assert TrustStore.from_dict(bundle["trust"]).hash == live.pin
    assert bundle["contract"]["policy_hash"] and bundle.get("policy"), sorted(bundle)  # RED
    assert bundle.get("checkpoint") and bundle.get("events"), sorted(bundle)  # RED


# ----- I: role isolation versus multi-role credentials ---------------------------------------------
def test_i1_green_control_single_role_principals_are_isolated(live):
    status, value = live.propose("sod", artifact(9), {"primary": 9}, token=ACTOR)
    assert status == 201, value
    assert live.act("sod", "approve", token=ACTOR)[1] == {"error": "ROLE_REQUIRED", "role": "owner"}
    assert live.act("sod", "approve", token=OWNER)[0] == 200


def test_i2_one_principal_cannot_both_propose_and_approve(live):
    """Reported: multi-role operator credentials are presented as signer isolation. Keys are
    per role, but one API principal holding actor and owner approves its own change. Required:
    the approving principal differs from the proposing principal (DECISION for root: or an
    explicit, visible single-operator mode instead)."""
    assert live.propose("self-approved", artifact(10), {"primary": 10}, token=RELEASE)[0] == 201
    status, value = live.act("self-approved", "approve", token=RELEASE)
    assert status in {403, 409} and value.get("error"), (status, value)  # RED at e3d3538: 200
    assert live.status("self-approved")["approved"] is False
