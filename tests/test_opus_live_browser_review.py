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
import os
import subprocess
import sys
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
from closure_engine.runtime.deployment import slug
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


LEGACY_PHASE = r"""
import json, sys, threading
from pathlib import Path
from closure_engine.runtime import (ROLES, Deployment, ReferenceTarget, ReferenceTargetServer,
    Runtime, enroll, enroll_target, init_identity)
root, port = Path(sys.argv[1]), int(sys.argv[2])
checks, window = json.loads(sys.argv[3]), json.loads(sys.argv[4])
def artifact(answer):
    routes = {"/answer": {"answer": answer}, "/config": {"mode": "safe"}, "/other": {"value": "stable"}}
    return json.dumps({"routes": routes}, sort_keys=True).encode()
deployment = Deployment(root / "ace")
for role in ROLES:
    init_identity(deployment.role_root(role), role, role + "-legacy")
pin = enroll(deployment, [c["id"] for c in checks])["trust_hash"]
target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{port}", checks)
ReferenceTarget.initialize(root / "target", artifact(1), target["deploy_token_sha256"])
server = ReferenceTargetServer(("127.0.0.1", port), root / "target")
threading.Thread(target=server.serve_forever, daemon=True).start()
runtime = Runtime(deployment, pin)
def drive(tx, raw, expect):
    runtime.propose("shop/api", tx, raw, intent="legacy " + tx, expect=expect, **window)
    for step in ("approve", "freeze", "baseline"):
        getattr(runtime, step)(tx)
    return runtime.run(tx)
squat = {"intent": "unrelated legacy squat", "expect": {"primary": 5}}
runtime.propose("shop/api", "victim/recovery", artifact(5), **squat)
release = drive("release/7", artifact(7), {"primary": 7})
runtime.accept("release/7")
failed = drive("victim", artifact(2), {"primary": 99})
server.shutdown(); server.server_close()
print(json.dumps({"pin": pin, "release": release["verdict"], "victim": [failed["verdict"], failed["state"]]}))
"""


def test_r1_legacy_collider_is_preserved_and_the_victim_still_recovers(tmp_path):
    """Reported: 'catalog-corrected-20261011/recovery' accepted 201 (namespace reservation).
    v2 (root's adopted repair): new ingress refuses such ids (R1); a collider that an OLDER release
    already stored is preserved byte for byte and the victim recovers through a fresh child bound
    to it. Real upgrade: the old wheel (ACE_LEGACY_PYTHON, e3d3538) writes the deployment, this
    interpreter (the repaired wheel) opens it. Also checks that a slash id the old release
    accepted stays addressable over the repaired API."""
    legacy = os.environ.get("ACE_LEGACY_PYTHON")
    if not legacy:
        pytest.skip("set ACE_LEGACY_PYTHON to an interpreter with the e3d3538 wheel installed")
    port = free_port()
    phase = subprocess.run(
        [legacy, "-I", "-c", LEGACY_PHASE, str(tmp_path), str(port), json.dumps(CHECKS), json.dumps(WINDOW)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert phase.returncode == 0, phase.stderr
    legacy_result = json.loads(phase.stdout.strip().splitlines()[-1])
    assert legacy_result["victim"] == ["DISPROVEN", "RECOVERY_REQUIRED"], legacy_result
    deployment = Deployment(tmp_path / "ace")
    collider_file = deployment.role_root("custodian") / "transactions" / (slug("victim/recovery") + ".json")
    original = collider_file.read_bytes()

    target = ReferenceTargetServer(("127.0.0.1", port), tmp_path / "target")
    runtime = Runtime(deployment, legacy_result["pin"])
    credentials = {hashlib.sha256(t.encode()).hexdigest(): p for t, p in TOKENS.items()}
    api = ApiServer(("127.0.0.1", 0), runtime, credentials)
    for s in (target, api):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        child = runtime.begin_recovery("victim")["transaction_id"]
        assert child != "victim/recovery", child
        for step in ("approve", "freeze", "baseline"):
            getattr(runtime, step)(child)
        assert runtime.run(child)["verdict"] == "PROVEN"
        assert runtime.complete_recovery("victim")["state"] == "RECOVERED"
        assert runtime.status(child)["parent_transaction"] == "victim"
        assert runtime.status("victim")["child_transaction"] == child
        assert collider_file.read_bytes() == original  # the legacy collider is evidence, untouched
        world = Live.__new__(Live)
        world.port = api.server_address[1]
        for legacy_id in ("release/7", "victim/recovery"):
            status, value = world.call("GET", "/api/v1/transactions/" + legacy_id, token=VIEWER)
            assert status == 200 and value["transaction_id"] == legacy_id, (legacy_id, status, value)
    finally:
        for s in (api, target):
            s.shutdown()
            s.server_close()


@pytest.mark.parametrize("tx", ["adv/../../evil", "a/./b", "..", ".", "a/.."])
def test_r2_dot_segment_ids_are_refused_before_storage(live, tx):
    """Reported: 'adv/../../evil' accepted 201 but unreachable 404 (browsers and curl remove dot
    segments before sending). An id that the product's own URLs cannot address must be refused."""
    folder = live.deployment.role_root("custodian") / "transactions"
    stored = sorted(p.name for p in folder.glob("*.json"))
    status, value = live.propose(tx, artifact(6), {"primary": 6})
    assert refused(status), (status, value)  # RED at e3d3538: 201
    assert tx not in live.listing_ids()
    assert sorted(p.name for p in folder.glob("*.json")) == stored  # no transaction record written


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
    # v2: aligned to root's adopted shape (signed receipt reason_code, operational view).
    deployment = view.get("deployment") or {}
    assert deployment.get("receipt") == "NOT_DEPLOYED", view  # RED at e3d3538: status has no receipt
    assert deployment.get("reason_code") == "ARTIFACT_FORMAT_INVALID", view  # target refused the format
    assert deployment.get("target_http_status") == 400, view
    assert isinstance(view.get("allowed_actions"), list), view  # RED at e3d3538
    assert "recover" not in view["allowed_actions"], view
    assert view["recovery"]["eligible"] is False, view
    # The reason is in the SIGNED broker receipt, not only in an unsigned view.
    receipts = live.runtime.custody.receipts("never-deployed")
    bodies = [r["payload"]["body"] for r in receipts]
    assert [b["status"] for b in bodies] == ["NOT_DEPLOYED"], bodies
    assert bodies[0]["reason_code"] == "ARTIFACT_FORMAT_INVALID", bodies


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
    # v2: aligned to root's adopted shape, bundle.portable; the legacy six fields stay.
    assert {"mode", "contract", "approval", "binding", "records", "receipts"} < set(bundle), sorted(bundle)
    proof = bundle.get("portable")
    assert isinstance(proof, dict), sorted(bundle)  # RED at e3d3538
    assert TrustStore.from_dict(proof["trust"]).hash == live.pin
    assert bundle["contract"]["policy_hash"] in proof["policies"], sorted(proof)
    pages = proof["pages"]
    assert pages and pages[-1]["checkpoint"] and any(page["events"] for page in pages)
    # Offline: a separate isolated interpreter, the downloaded file and the operator pin only.
    path = live.root / "portable-download.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    ok = offline_verify(path, live.pin, "portable")
    assert ok.returncode == 0 and '"PROVEN"' in ok.stdout, ok.stdout + ok.stderr
    # The bundled key is never the root: a foreign pin is refused ...
    attacker, attacker_pin = foreign_trust(live.root)
    wrong = offline_verify(path, attacker_pin, "portable")
    assert wrong.returncode != 0 and "TRUST_ANCHOR_MISMATCH" in wrong.stdout + wrong.stderr, wrong
    # ... and swapping in the foreign trust the attacker controls does not make the proof verify.
    forged = json.loads(json.dumps(bundle))
    forged["portable"]["trust"] = attacker.data
    forged_path = live.root / "portable-forged.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")
    swapped = offline_verify(forged_path, attacker_pin, "portable")
    assert swapped.returncode != 0 and "PROVEN" not in swapped.stdout, swapped


def offline_verify(path, pin, tx):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine.runtime.portable",
            "--bundle",
            str(path),
            "--expected-trust-hash",
            pin,
            "--expected-transaction",
            tx,
            "--require-proven",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_p3_one_transactions_proof_does_not_disclose_another_transactions_artifact(live):
    """NEW (Opus, not reviewer-reported): a portable proof is meant to be handed to a third party.
    The adopted export carries the global signed ledger (needed to authenticate the chain) and
    every evidence object reachable from it. Signed events are enough for chain authentication;
    another transaction's deployed artifact BYTES are not needed to replay this transaction."""
    from closure_engine.protocol import digest

    secret = artifact(12, other="customer-b-private-config")
    live.drive("tenant-b", secret, {"primary": 12})
    # v3: an unrelated change in between, so tenant-b's artifact is NOT tenant-a's baseline. In the
    # a203ee0 order (b then a) b's deployed bytes WERE a's baseline, which a's proof legitimately needs.
    live.drive("tenant-c", artifact(13), {"primary": 13})
    live.drive("tenant-a", artifact(8), {"primary": 8})
    status, bundle = live.call("GET", "/api/v1/transactions/tenant-a/bundle", token=VIEWER)
    assert status == 200, bundle
    assert bundle["contract"]["baseline_hash"] != digest(secret)  # guard: b is unrelated to a
    assert "portable" in bundle, sorted(bundle)  # no vacuous pass on a build without portable proofs
    evidence = bundle.get("portable", {}).get("evidence", {})
    assert digest(secret) not in evidence, "tenant-b's artifact bytes ship inside tenant-a's proof"
    assert base64.b64encode(secret).decode() not in json.dumps(bundle)


# ----- I: role isolation versus multi-role credentials ---------------------------------------------
def test_i1_green_control_single_role_principals_are_isolated(live):
    status, value = live.propose("sod", artifact(9), {"primary": 9}, token=ACTOR)
    assert status == 201, value
    assert live.act("sod", "approve", token=ACTOR)[1] == {"error": "ROLE_REQUIRED", "role": "owner"}
    assert live.act("sod", "approve", token=OWNER)[0] == 200


def test_i2_multi_role_login_is_a_visible_single_operator_mode(live):
    """Reported: multi-role operator credentials are presented as signer isolation.
    v2 (root decision 2026-10-11, the alternative the b4704ad probe offered): a multi-role login is
    an explicit, VISIBLE single-operator administration mode; distinct role-scoped principals stay
    enforced (I1). This is not human separation-of-duties and must never be labelled independent."""
    status, admin = live.call("GET", "/api/v1/whoami", token=RELEASE)
    assert status == 200 and isinstance(admin.get("approval_mode"), str), admin  # RED at e3d3538
    status, owner = live.call("GET", "/api/v1/whoami", token=OWNER)
    assert status == 200 and isinstance(owner.get("approval_mode"), str), owner
    assert admin["approval_mode"] != owner["approval_mode"], (admin, owner)
    assert "single" in admin["approval_mode"].lower(), admin
    assert "independent" not in json.dumps(admin).lower(), admin
    # The mode is a label on the same enforcement, not a bypass: role scoping still applies.
    assert live.propose("mode-check", artifact(10), {"primary": 10}, token=OWNER)[1] == {
        "error": "ROLE_REQUIRED",
        "role": "actor",
    }
