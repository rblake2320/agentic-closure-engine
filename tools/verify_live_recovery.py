"""Execute a bounded real disagreement and verified restoration on an operator-owned local target."""

import argparse
import base64
import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8782")
    parser.add_argument("--target-url", default="http://127.0.0.1:8784")
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--transaction", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--expect", required=True, help="JSON map: independently desired primary values")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    token = Path(args.token_file).read_text().strip()
    observations = []

    def call(base, path, body=None, authenticate=True):
        address = urlsplit(base)
        if address.scheme != "http" or address.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("This operational check is limited to explicit owned loopback endpoints")
        connection = http.client.HTTPConnection(address.hostname, address.port, timeout=120)
        headers = {"Authorization": "Bearer " + token} if authenticate else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(
            "GET" if body is None else "POST",
            path,
            body=None if body is None else json.dumps(body).encode(),
            headers=headers,
        )
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        value = json.loads(raw)
        observations.append({"path": path, "http_status": response.status, "response": value})
        assert 200 <= response.status < 300, value
        return value

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    try:
        before = call(args.target_url, "/ace/v1/state", authenticate=False)
        tx = args.transaction
        call(
            args.url,
            "/api/v1/transactions",
            {
                "target_id": args.target,
                "transaction_id": tx,
                "artifact_base64": base64.b64encode(Path(args.artifact).read_bytes()).decode(),
                "intent": (
                    "Verify refusal of a deployed catalog value that disagrees with the approved outcome, "
                    "then restore the observed baseline."
                ),
                "expect": json.loads(args.expect),
                "duration_ms": 10000,
                "min_samples": 3,
            },
        )
        review = call(args.url, f"/api/v1/transactions/{tx}/contract")
        assert {k: v["equals"] for k, v in review["evaluator"]["criteria"].items()} == json.loads(args.expect)
        for action in ("approve", "freeze", "baseline", "run"):
            failed = call(args.url, f"/api/v1/transactions/{tx}/{action}", {})
        assert failed["verdict"] == "DISPROVEN", failed
        deployed = call(args.target_url, "/ace/v1/state", authenticate=False)
        assert deployed["artifact_hash"] != before["artifact_hash"], deployed
        recovery = call(args.url, f"/api/v1/transactions/{tx}/recover", {})
        child = recovery["transaction_id"]
        for action in ("approve", "freeze", "baseline", "run"):
            restored = call(args.url, f"/api/v1/transactions/{child}/{action}", {})
        assert restored["verdict"] == "PROVEN", restored
        recovered = call(args.url, f"/api/v1/transactions/{tx}/recover-complete", {})
        assert recovered["state"] == "RECOVERED", recovered
        after = call(args.target_url, "/ace/v1/state", authenticate=False)
        assert after["artifact_hash"] == before["artifact_hash"], after
        original = call(args.url, f"/api/v1/transactions/{tx}")
        assert original["verdict"] == "DISPROVEN", original
        receipt = {
            "result": "Worked",
            "before": before,
            "deployed": deployed,
            "restored": after,
            "original_verdict": "DISPROVEN",
            "recovery_verdict": "PROVEN",
            "recovery_state": "RECOVERED",
            "observations": observations,
        }
    except BaseException as exc:
        (out / "receipt.json").write_text(
            json.dumps({"result": "Failed", "error": str(exc), "observations": observations}, indent=2)
        )
        raise
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {"result": "Worked", "transaction": tx, "recovery": child, "receipt": str(out / "receipt.json")}
        )
    )


if __name__ == "__main__":
    main()
