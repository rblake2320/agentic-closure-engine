"""O-03 trust anchor: verification commands require an operator-supplied expected trust hash.

A self-consistent substitute world (new keys under the same issuer names, its own ledger,
checkpoint and packet) verifies without a pin. With the pin from the original enrollment it
must fail closed before any evidence store or ledger is opened.
"""

import json
import subprocess
import sys

import pytest

from closure_engine.crypto import TrustStore

COMMANDS = ("evaluate-run", "verify-packet", "verify-ledger")


def command(*args):
    return subprocess.run(
        [sys.executable, "-I", "-m", "closure_engine", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=60,
    )


def world(path):
    result = command("demo", "--output", path)
    assert result.returncode == 0, result.stderr
    info = json.loads(result.stdout)
    pin = TrustStore.from_dict(json.loads((path / "trust.json").read_bytes())).hash
    return info, pin


@pytest.fixture(scope="module")
def worlds(tmp_path_factory):
    root = tmp_path_factory.mktemp("trust-anchor")
    original, original_pin = world(root / "original")
    forged, forged_pin = world(root / "forged")
    assert original_pin != forged_pin  # same issuer names, different enrolled keys
    return root, original, original_pin, forged, forged_pin


def args_for(name, folder, info, store=None, ledger=None):
    store = store or folder / "evidence"
    if name == "evaluate-run":
        return [
            name,
            "--bundle",
            folder / "run.json",
            "--trust",
            folder / "trust.json",
            "--store",
            store,
            "--at",
            info["evaluated_at"],
        ]
    if name == "verify-packet":
        return [
            name,
            "--packet",
            folder / "closure-packet.json",
            "--trust",
            folder / "trust.json",
            "--store",
            store,
        ]
    return [
        name,
        "--ledger",
        ledger or folder / "ledger.sqlite",
        "--trust",
        folder / "trust.json",
        "--store",
        store,
        "--checkpoint",
        folder / "checkpoint.json",
    ]


def error_of(result):
    return json.loads(result.stderr.strip().splitlines()[-1])["error"]


@pytest.mark.parametrize("name", COMMANDS)
def test_valid_control_matching_pin_verifies(worlds, name):
    root, original, pin, _, _ = worlds
    result = command(*args_for(name, root / "original", original), "--expected-trust-hash", pin)
    assert result.returncode == 0, result.stderr
    if name == "verify-ledger":
        assert json.loads(result.stdout)["verified_head"] == original["ledger_head"]


@pytest.mark.parametrize("name", COMMANDS)
def test_forged_world_verifies_under_its_own_pin_control(worlds, name):
    # Control for the attack: the substitute world is internally valid, so only the
    # independently supplied anchor can distinguish it.
    root, _, _, forged, forged_pin = worlds
    result = command(*args_for(name, root / "forged", forged), "--expected-trust-hash", forged_pin)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", COMMANDS)
def test_swapped_enrollment_rejected_before_store_or_ledger_admission(worlds, name):
    root, _, original_pin, forged, _ = worlds
    fresh_store = root / ("never-created-" + name)
    missing_ledger = root / ("missing-" + name + ".sqlite")
    result = command(
        *args_for(name, root / "forged", forged, store=fresh_store, ledger=missing_ledger),
        "--expected-trust-hash",
        original_pin,
    )
    assert result.returncode == 2, result.stdout
    assert error_of(result) == "TRUST_ANCHOR_MISMATCH"
    assert not fresh_store.exists(), "evidence store opened before the trust anchor was checked"
    assert not missing_ledger.exists()


@pytest.mark.parametrize("name", COMMANDS)
@pytest.mark.parametrize(
    "bad",
    ["", "sha256:", "sha256:" + "A" * 64, "sha256:" + "0" * 63, "md5:" + "0" * 64, " sha256:" + "0" * 64],
)
def test_malformed_pin_is_typed_error(worlds, name, bad):
    root, original, _, _, _ = worlds
    fresh_store = root / ("never-created-malformed-" + name)
    result = command(
        *args_for(name, root / "original", original, store=fresh_store), "--expected-trust-hash", bad
    )
    assert result.returncode == 2, result.stdout
    assert error_of(result) == "INVALID_TRUST_ANCHOR"
    assert not fresh_store.exists()


@pytest.mark.parametrize("name", COMMANDS)
def test_pin_is_required_not_discovered(worlds, name):
    root, original, _, _, _ = worlds
    result = command(*args_for(name, root / "original", original))
    assert result.returncode == 2, result.stdout
    assert "--expected-trust-hash" in result.stderr


def test_demo_remains_fixture_only_without_pin(tmp_path):
    result = command("demo", "--output", tmp_path / "demo")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["mode"] == "offline-fixture"
