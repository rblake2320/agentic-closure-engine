"""T0 product defects found by the reality audit (2026-10-11).

verify-ledger must report the actual transactions in any ledger, never a hard-coded fixture
name, and verification commands must never create missing evidence/ledger locations.
"""

import json
import subprocess
import sys

import pytest
from test_ledger import begin, event

from closure_engine.protocol import canonical, timestamp


def command(*args):
    return subprocess.run(
        [sys.executable, "-I", "-m", "closure_engine", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=60,
    )


def error_of(result):
    return json.loads(result.stderr.strip().splitlines()[-1])["error"]


@pytest.fixture
def customer_ledger(run, tmp_path):
    """A ledger whose transaction is not named like any demo fixture."""
    ledger = begin(run, tmp_path)  # transaction-1 reaches EXECUTING
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    (tmp_path / "trust.json").write_bytes(canonical(run["trust"].data))
    checkpoint = ledger.checkpoint(run["keys"]["custodian"], timestamp(run["start"]))
    (tmp_path / "checkpoint.json").write_bytes(canonical(checkpoint))
    return tmp_path, run["trust"].hash, ledger


def ledger_args(root, pin, store=None, ledger=None):
    return [
        "verify-ledger",
        "--ledger",
        ledger or root / "ledger.sqlite",
        "--trust",
        root / "trust.json",
        "--expected-trust-hash",
        pin,
        "--store",
        store or root / "evidence",
        "--checkpoint",
        root / "checkpoint.json",
    ]


def test_verify_ledger_enumerates_actual_transactions(customer_ledger):
    root, pin, ledger = customer_ledger
    result = command(*ledger_args(root, pin))
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["transactions"] == {"transaction-1": "VERIFYING"}
    assert body["sequence"] == ledger.sequence and body["verified_head"] == ledger.head


def test_verify_ledger_selects_named_transaction(customer_ledger):
    root, pin, _ = customer_ledger
    result = command(*ledger_args(root, pin), "--transaction", "transaction-1")
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["transaction"] == "transaction-1" and body["state"] == "VERIFYING"


def test_verify_ledger_unknown_transaction_is_typed_error(customer_ledger):
    root, pin, _ = customer_ledger
    result = command(*ledger_args(root, pin), "--transaction", "fixture-transaction")
    assert result.returncode == 2
    assert error_of(result) == "TRANSACTION_UNKNOWN"


def test_verify_ledger_never_creates_missing_store(customer_ledger):
    root, pin, _ = customer_ledger
    missing = root / "typo" / "evidnce"
    result = command(*ledger_args(root, pin, store=missing))
    assert result.returncode == 2
    assert error_of(result) == "EVIDENCE_STORE_MISSING"
    assert not missing.exists() and not missing.parent.exists()


def test_verify_ledger_never_creates_missing_ledger_location(customer_ledger):
    root, pin, _ = customer_ledger
    missing = root / "nowhere" / "ledger.sqlite"
    result = command(*ledger_args(root, pin, ledger=missing))
    assert result.returncode == 2
    assert error_of(result) == "LEDGER_MISSING"
    assert not missing.parent.exists()


@pytest.mark.parametrize("name", ["verify-packet", "evaluate-run"])
def test_verify_paths_never_create_missing_store(tmp_path, name):
    demo = command("demo", "--output", tmp_path / "demo")
    assert demo.returncode == 0, demo.stderr
    info = json.loads(demo.stdout)
    missing = tmp_path / "typo" / "evidnce"
    base = [
        "--trust",
        tmp_path / "demo" / "trust.json",
        "--expected-trust-hash",
        info["trust_hash"],
        "--store",
        missing,
    ]
    if name == "verify-packet":
        args = [name, "--packet", tmp_path / "demo" / "closure-packet.json", *base]
    else:
        args = [name, "--bundle", tmp_path / "demo" / "run.json", *base, "--at", info["evaluated_at"]]
    result = command(*args)
    assert result.returncode == 2
    assert error_of(result) == "EVIDENCE_STORE_MISSING"
    assert not missing.exists() and not missing.parent.exists()


def test_valid_control_existing_store_verifies(tmp_path):
    demo = command("demo", "--output", tmp_path / "demo")
    info = json.loads(demo.stdout)
    result = command(
        "verify-packet",
        "--packet",
        tmp_path / "demo" / "closure-packet.json",
        "--trust",
        tmp_path / "demo" / "trust.json",
        "--expected-trust-hash",
        info["trust_hash"],
        "--store",
        tmp_path / "demo" / "evidence",
    )
    assert result.returncode == 0, result.stderr
