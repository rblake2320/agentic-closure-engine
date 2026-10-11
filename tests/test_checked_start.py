"""OW-01: wrappers start ACE through Invoke-CheckedProductStart (tools/checked-start.ps1), which
must turn a refused or failed start into a terminating ACE_START_FAILED error instead of letting
the caller continue and report success. Real PowerShell processes against a real held host lock;
every case stops before Docker and before any signing identity is touched (no target profile)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(os.environ.get("ACE_TEST_TOOLS_DIR", Path(__file__).parents[1] / "tools"))
SHELLS = [shell for shell in (shutil.which("pwsh"), shutil.which("powershell")) if shell]
pytestmark = pytest.mark.skipif(not SHELLS, reason="PowerShell is required")

# A caller shaped like backup/restore: Stop preference, the helper dot-sourced by absolute path,
# a success line that must never print after a refused start.
CALLER = r"""
param([string]$Tools, [string]$Runtime)
$ErrorActionPreference = 'Stop'
. (Join-Path $Tools 'checked-start.ps1')
try {
    Invoke-CheckedProductStart @{RuntimeDirectory=$Runtime} 'Saved state is at SAVED-STATE-MARKER.'
    [Console]::Out.WriteLine('CONTINUED')
} catch {
    [Console]::Out.WriteLine('CAUGHT: ' + $_.Exception.Message)
    exit 3
}
"""


def holder(shell, lock):
    """A separate process that holds the host startup lock until told to release it."""
    script = (
        f"$f=[IO.File]::Open('{lock}','OpenOrCreate','ReadWrite','None');"
        "[Console]::Out.WriteLine('HELD');[Console]::Out.Flush();"
        "[void][Console]::In.ReadLine();$f.Dispose()"
    )
    process = subprocess.Popen(
        [shell, "-NoProfile", "-NonInteractive", "-Command", script],
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


def run_caller(shell, tmp_path, lock, cwd):
    caller = tmp_path / "caller" / "caller.ps1"
    caller.parent.mkdir(exist_ok=True)
    caller.write_text(CALLER, encoding="utf-8")
    runtime = tmp_path / "runtime"
    env = dict(os.environ, ACE_START_LOCK=str(lock))
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(caller),
            "-Tools",
            str(TOOLS),
            "-Runtime",
            str(runtime),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=120,
    )
    return result, runtime


@pytest.mark.parametrize("shell", SHELLS)
def test_busy_start_terminates_the_caller_with_ace_start_failed(shell, tmp_path):
    lock = tmp_path / "start.lock"
    lock_holder = holder(shell, lock)
    try:
        result, runtime = run_caller(shell, tmp_path, lock, cwd=tmp_path)
    finally:
        release(lock_holder)
    output = result.stdout + result.stderr
    assert result.returncode == 3, output
    assert "CONTINUED" not in result.stdout, output
    caught = [line for line in result.stdout.splitlines() if line.startswith("CAUGHT: ")]
    assert len(caught) == 1, output
    message = caught[0][len("CAUGHT: ") :]
    assert message.startswith("ACE_START_FAILED: "), message
    assert "exit 75" in message and "SAVED-STATE-MARKER" in message, message
    assert "ACE_START_BUSY" in result.stderr, output
    assert not runtime.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_helper_starts_its_own_product_script_not_one_from_the_working_directory(shell, tmp_path):
    # A decoy start-product.ps1 that would "succeed" sits wherever a relative lookup could find it.
    marker = tmp_path / "decoy-ran"
    decoy = f"New-Item -ItemType File -Path '{marker}' | Out-Null; exit 0"
    for decoy_path in (tmp_path / "start-product.ps1", tmp_path / "tools" / "start-product.ps1"):
        decoy_path.parent.mkdir(exist_ok=True)
        decoy_path.write_text(decoy, encoding="utf-8")
    lock = tmp_path / "start.lock"
    lock_holder = holder(shell, lock)
    try:
        result, _ = run_caller(shell, tmp_path, lock, cwd=tmp_path)
    finally:
        release(lock_holder)
    output = result.stdout + result.stderr
    assert not marker.exists(), output
    assert result.returncode == 3 and "CONTINUED" not in result.stdout, output
    assert "CAUGHT: ACE_START_FAILED: " in result.stdout and "exit 75" in result.stdout, output


@pytest.mark.parametrize("shell", SHELLS)
def test_start_that_fails_after_acquiring_the_lock_also_stops_the_caller(shell, tmp_path):
    # Lock free: start-product acquires it, then refuses on its own precondition (no target profile).
    result, runtime = run_caller(shell, tmp_path, tmp_path / "start.lock", cwd=tmp_path)
    output = result.stdout + result.stderr
    assert result.returncode == 3 and "CONTINUED" not in result.stdout, output
    assert "First installation requires -TargetProfile" in result.stdout, output
    assert "ACE_START_BUSY" not in result.stderr, output
    # The lock was released on that failure path: a new holder acquires it immediately.
    release(holder(shell, tmp_path / "start.lock"))
