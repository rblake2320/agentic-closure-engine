import json
import subprocess
import sys


def command(*args):
    return subprocess.run(
        [sys.executable, "-I", "-m", "closure_engine", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_installed_cli_demo_and_independent_replay(tmp_path):
    output = tmp_path / "public-demo"
    demo = command("demo", "--output", output)
    assert demo.returncode == 0, demo.stderr
    result = json.loads(demo.stdout)
    assert result["mode"] == "offline-fixture" and result["verdict"] == "PROVEN"
    replay = command(
        "evaluate-run",
        "--bundle",
        output / "run.json",
        "--trust",
        output / "trust.json",
        "--expected-trust-hash",
        result["trust_hash"],
        "--store",
        output / "evidence",
        "--at",
        result["evaluated_at"],
        "--require-proven",
    )
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout)["verdict"] == "PROVEN"
    checkpoint = command(
        "verify-ledger",
        "--ledger",
        output / "ledger.sqlite",
        "--trust",
        output / "trust.json",
        "--expected-trust-hash",
        result["trust_hash"],
        "--store",
        output / "evidence",
        "--checkpoint",
        output / "checkpoint.json",
    )
    assert checkpoint.returncode == 0, checkpoint.stderr
    assert json.loads(checkpoint.stdout)["state"] == "ACCEPTED"
    assert not list(output.rglob("*.key")) and not list(output.rglob("*.pem"))


def test_cli_rejects_existing_output_and_malformed_input(tmp_path):
    target = tmp_path / "occupied"
    target.mkdir()
    keep = target / "keep.txt"
    keep.write_text("owner data")
    result = command("demo", "--output", target)
    assert result.returncode != 0
    assert keep.read_text() == "owner data"
    assert json.loads(result.stderr)["error"] == "OUTPUT_NOT_EMPTY"


def test_cli_failed_invariant_cannot_require_proven(tmp_path):
    output = tmp_path / "failure"
    demo = command("demo", "--output", output, "--scenario", "invariant-failure")
    assert demo.returncode == 0, demo.stderr
    result = json.loads(demo.stdout)
    assert result["verdict"] == "DISPROVEN"
    replay = command(
        "evaluate-run",
        "--bundle",
        output / "run.json",
        "--trust",
        output / "trust.json",
        "--expected-trust-hash",
        result["trust_hash"],
        "--store",
        output / "evidence",
        "--at",
        result["evaluated_at"],
        "--require-proven",
    )
    assert replay.returncode == 3
    assert json.loads(replay.stdout)["verdict"] == "DISPROVEN"
