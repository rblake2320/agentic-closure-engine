"""RR-01: start-product.ps1 holds an exclusive host startup lock across the single-authority
check and compose up. Real concurrent PowerShell processes against a real lock holder; every
case stops before Docker and before any signing identity is touched (no target profile)."""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

SHELL = os.environ.get("ACE_TEST_POWERSHELL") or shutil.which("pwsh") or shutil.which("powershell")
SCRIPT = Path(
    os.environ.get("ACE_TEST_START_SCRIPT", Path(__file__).parents[1] / "tools" / "start-product.ps1")
)
pytestmark = pytest.mark.skipif(SHELL is None, reason="PowerShell is required")


def start(runtime, lock):
    env = dict(os.environ, ACE_START_LOCK=str(lock))
    return subprocess.Popen(
        [SHELL, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT), "-RuntimeDirectory", str(runtime)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def holder(lock):
    """A separate process that holds the startup lock until told to release it."""
    script = (
        f"$f=[IO.File]::Open('{lock}','OpenOrCreate','ReadWrite','None');"
        "[Console]::Out.WriteLine('HELD');[Console]::Out.Flush();"
        "[void][Console]::In.ReadLine();$f.Dispose()"
    )
    process = subprocess.Popen(
        [SHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout.readline().strip() == "HELD", process.stderr.read()
    return process


def release(process):
    process.stdin.write("\n")
    process.stdin.flush()
    process.wait(timeout=30)


def test_concurrent_starts_are_refused_busy_before_any_write(tmp_path):
    lock = tmp_path / "start.lock"
    lock_holder = holder(lock)
    try:
        runs = [start(tmp_path / name, lock) for name in ("runtime-a", "runtime-b")]
        results = [(p.wait(timeout=60), p.stderr.read()) for p in runs]
    finally:
        release(lock_holder)
    for code, stderr in results:
        assert code == 75, stderr
        assert "ACE_START_BUSY" in stderr
    assert not (tmp_path / "runtime-a").exists() and not (tmp_path / "runtime-b").exists()


def test_lock_is_released_when_startup_fails(tmp_path):
    lock = tmp_path / "start.lock"
    for attempt in ("first", "second"):
        process = start(tmp_path / "runtime-c", lock)
        code, stderr = process.wait(timeout=60), process.stderr.read()
        # The run acquired the lock, then failed on its own precondition (no target profile)...
        assert code != 75 and "ACE_START_BUSY" not in stderr, (attempt, stderr)
        assert "First installation requires -TargetProfile" in stderr, (attempt, stderr)
    # ...and released it on that failure path: a new holder acquires it immediately.
    started = time.monotonic()
    release(holder(lock))
    assert time.monotonic() - started < 20


def test_busy_refusal_is_deterministic_while_held(tmp_path):
    lock = tmp_path / "start.lock"
    lock_holder = holder(lock)
    try:
        codes = []
        for index in range(3):
            process = start(tmp_path / f"runtime-{index}", lock)
            codes.append(process.wait(timeout=60))
    finally:
        release(lock_holder)
    assert codes == [75, 75, 75]
