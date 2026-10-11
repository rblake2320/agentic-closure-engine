"""Custody restart: a brand-new ledger must be reopenable by a later process, and a ledger whose
checkpoint has gone missing must still be refused (never silently re-anchored). Each step runs
as a separate process through the shipped CLI."""

import json
import subprocess
import sys

from test_runtime_e2e import artifact, expect_of, world  # noqa: F401 - fixture

from closure_engine.protocol import GENESIS
from closure_engine.runtime import ROLES, Deployment, Runtime, enroll, init_identity


def ace(*args):
    return subprocess.run(
        [sys.executable, "-I", "-m", "closure_engine", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=120,
    )


def status(deployment, pin):
    return ace("status", "--deployment", deployment.root, "--expected-trust-hash", pin)


def fresh(tmp_path):
    deployment = Deployment(tmp_path / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-rs")
    return deployment, enroll(deployment, ["primary"])["trust_hash"]


def test_empty_installation_survives_process_restart(tmp_path):
    deployment, pin = fresh(tmp_path)
    first = status(deployment, pin)
    assert first.returncode == 0, first.stderr
    custody = deployment.role_root("custodian")
    assert (custody / "ledger.sqlite").exists()
    checkpoint = json.loads((custody / "checkpoint.json").read_bytes())
    assert (
        checkpoint["payload"]["body"]["sequence"] == 0
        and checkpoint["payload"]["body"]["head_hash"] == GENESIS
    )
    second = status(deployment, pin)  # a new process reopening the existing empty ledger
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)["sequence"] == 0


def test_nonempty_ledger_reopens_in_a_new_process(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose("shop/api", "rs-1", artifact(2), intent="restart", expect=expect_of(artifact(2)))
    runtime.approve("rs-1")
    reopened = status(deployment, pin)
    assert reopened.returncode == 0, reopened.stderr
    assert json.loads(reopened.stdout)["transactions"] == {"rs-1": "APPROVED"}


def test_missing_checkpoint_on_existing_history_is_refused_not_regenerated(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose("shop/api", "rs-2", artifact(3), intent="restart", expect=expect_of(artifact(3)))
    runtime.approve("rs-2")
    checkpoint = deployment.role_root("custodian") / "checkpoint.json"
    checkpoint.unlink()
    refused = status(deployment, pin)
    assert refused.returncode == 2 and "CHECKPOINT_MISSING" in refused.stderr
    assert not checkpoint.exists()  # no silent re-anchoring of existing history


def test_missing_checkpoint_on_existing_empty_ledger_is_refused(tmp_path):
    deployment, pin = fresh(tmp_path)
    assert status(deployment, pin).returncode == 0
    (deployment.role_root("custodian") / "checkpoint.json").unlink()
    refused = status(deployment, pin)
    assert refused.returncode == 2 and "CHECKPOINT_MISSING" in refused.stderr


def test_checkpoint_beyond_a_deleted_ledger_is_refused(world):  # noqa: F811
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose("shop/api", "rs-3", artifact(4), intent="restart", expect=expect_of(artifact(4)))
    runtime.approve("rs-3")
    (deployment.role_root("custodian") / "ledger.sqlite").unlink()  # history removed, anchor kept
    refused = status(deployment, pin)
    assert refused.returncode == 2 and "CHECKPOINT_MISMATCH_OR_TRUNCATION" in refused.stderr
