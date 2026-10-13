"""Build an ACE wheel and retain installed kernel/runtime checks and legacy CLI controls."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import venv
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "valid": "PROVEN",
    "invariant-failure": "DISPROVEN",
    "evaluator-tamper": "DISPROVEN",
    "old-artifact": "INDETERMINATE",
    "missing-deployment": "INDETERMINATE",
    "not-deployed": "PARTIALLY_PROVEN",
    "unreachable": "INDETERMINATE",
    "signature-failure": "INDETERMINATE",
    "interrupted": "INDETERMINATE",
    "stale": "INDETERMINATE",
    "replay": "PROVEN",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit("Verification output must be a new empty directory")
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTEST_PLUGINS"] = ""
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTHONPATH", None)
    commands = []

    def run(command, label, *, expected=0, cwd=ROOT):
        started = time.monotonic()
        try:
            completed = subprocess.run(
                list(map(str, command)),
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                # The installed suite includes real observation/recovery windows and
                # TLS witness processes. The former900s bound expired after >95%
                # of528 cases; this bounds the harness, not any closure contract.
                timeout=1800 if label == "installed-tests" else 300,
            )
        except subprocess.TimeoutExpired as exc:

            def decoded(value):
                return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""

            (out / (label + ".stdout.txt")).write_text(decoded(exc.stdout), encoding="utf-8")
            (out / (label + ".stderr.txt")).write_text(decoded(exc.stderr), encoding="utf-8")
            (out / (label + ".timeout.json")).write_text(
                json.dumps(
                    {
                        "result": "Failed",
                        "check": label,
                        "cause": "COMMAND_TIMEOUT",
                        "timeout_seconds": exc.timeout,
                        "duration_ms": int((time.monotonic() - started) * 1000),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            raise
        (out / (label + ".stdout.txt")).write_text(completed.stdout, encoding="utf-8")
        (out / (label + ".stderr.txt")).write_text(completed.stderr, encoding="utf-8")
        commands.append(
            {
                "check": label,
                "exit_code": completed.returncode,
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
        )
        if completed.returncode != expected:
            raise RuntimeError(f"{label} failed with exit {completed.returncode}: {completed.stderr[-1000:]}")
        print(json.dumps({"check": label, "result": "Worked"}), flush=True)
        return completed.stdout

    run([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", out / "wheels"], "build")
    wheels = list((out / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Expected exactly one newly built wheel")
    wheel = wheels[0]
    fresh = out / "venv"
    venv.EnvBuilder(with_pip=True).create(fresh)
    python = fresh / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run(
        [python, "-m", "pip", "install", "--require-hashes", "-r", ROOT / "requirements.lock"], "dependencies"
    )
    run([python, "-m", "pip", "install", "--no-deps", wheel], "install")
    origin = json.loads(
        run(
            [
                python,
                "-I",
                "-c",
                'import closure_engine,json,sys; print(json.dumps({"module":closure_engine.__file__, '
                '"python":sys.version}))',
            ],
            "installed-origin",
            cwd=out,
        )
    )
    if Path(origin["module"]).is_relative_to(ROOT / "src") or "site-packages" not in origin["module"]:
        raise RuntimeError("Acceptance imported source instead of installed wheel")
    run(
        [
            python,
            "-I",
            "-m",
            "pytest",
            ROOT / "tests",
            "-o",
            "pythonpath=",
            "-q",
            "--durations=20",
            "--junitxml",
            out / "tests.xml",
            "--basetemp",
            out / "pytest-temp",
        ],
        "installed-tests",
        cwd=out,
    )
    results = []
    for scenario, expected in EXPECTED.items():
        target = out / "scenarios" / scenario
        result = json.loads(
            run(
                [python, "-I", "-m", "closure_engine", "demo", "--output", target, "--scenario", scenario],
                "demo-" + scenario,
                cwd=out,
            )
        )
        if result["verdict"] != expected or result["mode"] != "offline-fixture":
            raise RuntimeError(f"Wrong kernel outcome for {scenario}")
        replay = json.loads(
            run(
                [
                    python,
                    "-I",
                    "-m",
                    "closure_engine",
                    "evaluate-run",
                    "--bundle",
                    target / "run.json",
                    "--trust",
                    target / "trust.json",
                    "--expected-trust-hash",
                    result["trust_hash"],
                    "--store",
                    target / "evidence",
                    "--at",
                    result["evaluated_at"],
                ],
                "replay-" + scenario,
                cwd=out,
            )
        )
        if replay["verdict"] != expected:
            raise RuntimeError(f"Independent CLI replay disagreed for {scenario}")
        run(
            [
                python,
                "-I",
                "-m",
                "closure_engine",
                "verify-ledger",
                "--ledger",
                target / "ledger.sqlite",
                "--trust",
                target / "trust.json",
                "--expected-trust-hash",
                result["trust_hash"],
                "--store",
                target / "evidence",
                "--checkpoint",
                target / "checkpoint.json",
            ],
            "ledger-" + scenario,
            cwd=out,
        )
        results.append(
            {
                "scenario": scenario,
                "expected": expected,
                "observed": result["verdict"],
                "packet_hash": result["packet_hash"],
                "ledger_head": result["ledger_head"],
            }
        )
    inventory = json.loads(
        run(
            [
                python,
                "-I",
                "-c",
                "import importlib.metadata as m,json; print(json.dumps(sorted("
                '[{"name":d.metadata["Name"],"version":d.version} for d in m.distributions()],'
                'key=lambda x:x["name"].lower())))',
            ],
            "installed-distributions",
            cwd=out,
        )
    )
    # Minimal CycloneDX inventory of this build/verification environment, not a production SBOM claim.
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "agentic-closure-engine",
                "version": next(p["version"] for p in inventory if p["name"] == "agentic-closure-engine"),
            }
        },
        "components": [{"type": "library", **p} for p in inventory],
    }
    (out / "sbom.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    suites = list(ET.parse(out / "tests.xml").getroot().iter("testsuite"))
    receipt = {
        "scope": "Installed ACE kernel and shipped runtime suite: real cryptography, filesystem, "
        "ledger, HTTP target, authenticated services and subprocess checks",
        "cli_scenario_scope": "Legacy synthetic evidence controls; real crypto and ledger I/O. "
        "Live deployment and Docker recovery receipts are retained separately.",
        "wheel": wheel.name,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "installed_origin": origin,
        "tests": sum(int(s.attrib.get("tests", 0)) for s in suites),
        "failures": sum(int(s.attrib.get("failures", 0)) + int(s.attrib.get("errors", 0)) for s in suites),
        "scenarios": results,
        "commands": commands,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "result": "Worked",
                "tests": receipt["tests"],
                "failures": receipt["failures"],
                "scenarios": len(results),
                "receipt": str(out / "receipt.json"),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
