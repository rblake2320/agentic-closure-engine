"""Real approved catalog change, portable offline proof, then exact baseline restoration."""

import argparse
import base64
import hashlib
import http.client
import json
import subprocess
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--actor-token", required=True)
    parser.add_argument("--owner-token", required=True)
    parser.add_argument("--operator-token", required=True)
    parser.add_argument("--viewer-token", required=True)
    parser.add_argument("--trust-pin-file", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    tokens = {
        name: Path(getattr(args, name + "_token")).read_text().strip()
        for name in ("actor", "owner", "operator", "viewer")
    }
    observations = []

    def call(path, body=None, *, identity="operator", port=8782, expected=200, raw=False):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=180)
        headers = {"Content-Type": "application/json"}
        if port == 8782:
            headers["Authorization"] = "Bearer " + tokens[identity]
        connection.request(
            "GET" if body is None else "POST",
            path,
            None if body is None else json.dumps(body).encode(),
            headers,
        )
        response = connection.getresponse()
        data = response.read()
        status = response.status
        connection.close()
        value = data if raw else json.loads(data)
        observations.append(
            {
                "path": path,
                "port": port,
                "identity": identity,
                "status": status,
                "state": value.get("state") if isinstance(value, dict) else None,
            }
        )
        assert status == expected, (path, status, value if not raw else "raw response")
        return value

    before = call("/ace/v1/state", port=8784)
    baseline = call("/ace/v1/artifact", port=8784, raw=True)
    assert "sha256:" + hashlib.sha256(baseline).hexdigest() == before["artifact_hash"]
    original = json.loads(baseline)
    assert set(original) == {"routes"}
    old_version = original["routes"]["/catalog"]["version"]
    changed = json.loads(baseline)
    changed["routes"]["/catalog"]["version"] = old_version + 1
    protected = {key: call(key, port=8784) for key in ("/access-policy", "/retention-policy")}
    packets = []
    try:
        for suffix, artifact, value in (
            ("publish", json.dumps(changed, separators=(",", ":")).encode(), old_version + 1),
            ("restore", baseline, old_version),
        ):
            transaction = args.prefix + "-" + suffix
            call(
                "/api/v1/transactions",
                {
                    "transaction_id": transaction,
                    "target_id": "release-catalog",
                    "artifact_base64": base64.b64encode(artifact).decode(),
                    "intent": "Owner-approved bounded catalog verification, then exact baseline restoration",
                    "expect": {"catalog-version": value},
                    "duration_ms": 10000,
                    "min_samples": 3,
                },
                identity="actor",
                expected=201,
            )
            denied = call(f"/api/v1/transactions/{transaction}/approve", {}, identity="actor", expected=403)
            assert denied == {"error": "ROLE_REQUIRED", "role": "owner"}
            criteria = call(f"/api/v1/transactions/{transaction}/contract", identity="owner")
            assert criteria["evaluator"]["criteria"]["catalog-version"]["equals"] == value
            call(f"/api/v1/transactions/{transaction}/approve", {}, identity="owner")
            for action in ("freeze", "baseline"):
                call(f"/api/v1/transactions/{transaction}/{action}", {})
            start = time.monotonic()
            result = call(f"/api/v1/transactions/{transaction}/run", {})
            assert result["verdict"] == "PROVEN", result
            assert time.monotonic() - start >= 9, "Observation window was bypassed"
            accepted = call(f"/api/v1/transactions/{transaction}/accept", {}, identity="owner")
            assert accepted["state"] == "ACCEPTED"
            bundle = call(f"/api/v1/transactions/{transaction}/bundle", identity="viewer", raw=True)
            (output / (suffix + "-bundle.json")).write_bytes(bundle)
            closure = call(f"/api/v1/transactions/{transaction}/closure", identity="viewer", raw=True)
            (output / (suffix + "-packet.json")).write_bytes(closure)
            pin = Path(args.trust_pin_file).read_text().strip()
            verify = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "closure_engine.runtime.portable",
                    "--bundle",
                    str(output / (suffix + "-bundle.json")),
                    "--expected-trust-hash",
                    pin,
                    "--expected-transaction",
                    transaction,
                    "--require-proven",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            (output / (suffix + "-offline.stdout.json")).write_text(verify.stdout)
            (output / (suffix + "-offline.stderr.txt")).write_text(verify.stderr)
            assert verify.returncode == 0, verify.stderr
            assert call("/catalog", port=8784)["version"] == value
            assert {key: call(key, port=8784) for key in protected} == protected
            packets.append(
                {
                    "transaction": transaction,
                    "verdict": result["verdict"],
                    "state": accepted["state"],
                    "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
                }
            )
        after = call("/ace/v1/state", port=8784)
        assert after["artifact_hash"] == before["artifact_hash"]
        assert call("/ace/v1/artifact", port=8784, raw=True) == baseline
        receipt = {
            "result": "Worked",
            "before": before,
            "after": after,
            "packets": packets,
            "observations": observations,
            "restoration": "Separate approved PROVEN transaction; original success remains ACCEPTED",
        }
    except BaseException as exc:
        (output / "receipt.json").write_text(
            json.dumps({"result": "Failed", "error": str(exc), "observations": observations}, indent=2)
        )
        raise
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2))
    print(json.dumps({"result": "Worked", "receipt": str(output / "receipt.json")}), flush=True)


if __name__ == "__main__":
    main()
