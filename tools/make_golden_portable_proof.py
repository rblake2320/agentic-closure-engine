"""Produce the committed ace.portable.v2 golden proof (tests/fixtures/portable_v2_golden/).

This is a REAL proof, not a fixture demo: fresh Ed25519 identities on disk, a real loopback
HTTP reference target, a real approved change deployed, observed, closed PROVEN and accepted,
then exported through the same ``export_bundle`` the API serves. The operator pin is written
to a separate file because the verifier must receive it independently of the proof.

Run from a checkout with the wheel or src importable:

    python -I tools/make_golden_portable_proof.py --out tests/fixtures/portable_v2_golden

Regenerate ONLY when a new proof format version is introduced; the point of the fixture is
that every later verifier keeps verifying this exact 0.3.1 proof (docs/PORTABLE_PROOF.md,
"Compatibility promise").
"""

import argparse
import hashlib
import json
import socket
import sys
import tempfile
import threading
from importlib.metadata import version
from pathlib import Path

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
from closure_engine.runtime.portable import encode_bundle

CHECKS = [
    {
        "id": "primary",
        "kind": "primary",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "http-json", "path": "/answer", "pointer": "/answer"},
    },
    {
        "id": "protected-config",
        "kind": "invariant",
        "phase": "window",
        "mandatory": True,
        "probe": {"type": "http-unchanged", "path": "/config"},
    },
    {
        "id": "protected-other",
        "kind": "invariant",
        "phase": "window",
        "mandatory": True,
        "probe": {"type": "http-unchanged", "path": "/other"},
    },
    {
        "id": "deployment",
        "kind": "deployment",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "active-artifact"},
    },
    {
        "id": "stage",
        "kind": "stage",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "staged-artifact"},
    },
    {
        "id": "baseline",
        "kind": "baseline",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "baseline-custody"},
    },
]
WINDOW = {"duration_ms": 3000, "min_samples": 3, "max_clock_skew_ms": 1000, "settle_ms": 2500}
TRANSACTION = "golden-portable-v2"


def artifact(answer):
    routes = {"/answer": {"answer": answer}, "/config": {"mode": "safe"}, "/other": {"value": "stable"}}
    return json.dumps({"routes": routes}, sort_keys=True).encode()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="Fixture directory (created or overwritten)")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ace-golden-") as temp:
        root = Path(temp)
        deployment = Deployment(root / "ace")
        for role in ROLES:
            init_identity(deployment.role_root(role), role, role + "-golden")
        pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
        port = free_port()
        target = enroll_target(deployment, "golden/target", f"http://127.0.0.1:{port}", CHECKS)
        ReferenceTarget.initialize(root / "target", artifact(1), target["deploy_token_sha256"])
        server = ReferenceTargetServer(("127.0.0.1", port), root / "target")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            runtime = Runtime(deployment, pin)
            raw = artifact(2)
            runtime.propose(
                "golden/target",
                TRANSACTION,
                raw,
                intent="Golden portable proof",
                expect={"primary": 2},
                **WINDOW,
            )
            runtime.approve(TRANSACTION)
            runtime.freeze(TRANSACTION)
            runtime.baseline(TRANSACTION)
            runtime.bind(TRANSACTION)
            deployed = runtime.deploy(TRANSACTION)
            if deployed["receipt"] != "EXECUTED":
                raise SystemExit(f"deployment receipt {deployed['receipt']!r}, expected EXECUTED")
            runtime.observe(TRANSACTION, phase="all")
            result = runtime.close(TRANSACTION)
            if result["state"] == "OBSERVING":
                result = runtime.close(TRANSACTION)
            if result.get("verdict") != "PROVEN":
                raise SystemExit(f"verdict {result.get('verdict')!r}, expected PROVEN: {result}")
            runtime.accept(TRANSACTION)
            encoded = encode_bundle(runtime.export_bundle(TRANSACTION))
        finally:
            server.shutdown()
            server.server_close()
    (out / "proof.json").write_bytes(encoded)
    (out / "trust-pin.txt").write_text(pin + "\n", encoding="utf-8")
    manifest = {
        "format": "ace.portable.v2",
        "produced_by": "agentic-closure-engine " + version("agentic-closure-engine"),
        "transaction_id": TRANSACTION,
        "expected_verdict": "PROVEN",
        "expected_artifact_hash": "sha256:" + hashlib.sha256(artifact(2)).hexdigest(),
        "proof_sha256": hashlib.sha256(encoded).hexdigest(),
        "proof_bytes": len(encoded),
        "note": "Real proof from a real loopback run; regenerate only for a new format version.",
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
