"""Exercise only a temporary viewer identity through shipped credential commands.

No Docker configuration inspection, signing keys, broker credentials or environment values are read.
The operator-owned auth volume is mounted only in a network-free UID11007 enrollment command.
"""

import argparse
import http.client
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--restart", action="store_true", help="Also check retained enrollment across a real product restart"
    )
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    private = (Path(".runtime/credential-proof") / out.name).resolve()
    private.mkdir(parents=True, exist_ok=False)
    mount = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "11007:11007",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--mount",
        "type=volume,source=agentic-closure-engine_gateway-auth,target=/auth",
        "--mount",
        f"type=bind,source={private},target=/export",
    ]
    observations, issued, revoked = [], [], set()

    def command(arguments):
        result = subprocess.run(
            mount + ["--entrypoint", "closure-engine", "agentic-closure-engine:0.3.0"] + arguments,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, {"exit": result.returncode, "stderr": result.stderr}
        value = json.loads(result.stdout)
        observations.append({"command": arguments[0], "response": value})
        return value

    def request(token, *, method="GET", action="", expected=200):
        connection = http.client.HTTPConnection("127.0.0.1", 8782, timeout=30)
        path = "/api/v1/transactions/catalog-corrected-20261011" + action
        headers = {"Authorization": "Bearer " + token}
        if method == "POST":
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=b"{}" if method == "POST" else None, headers=headers)
        response = connection.getresponse()
        value = json.loads(response.read())
        connection.close()
        observations.append(
            {
                "method": method,
                "action": action,
                "status": response.status,
                "state": value.get("state"),
                "error": value.get("error"),
            }
        )
        assert response.status == expected, value
        return value

    def revoke(digest):
        command(["api-revoke", "--credentials", "/auth", "--token-sha256", digest])
        revoked.add(digest)

    try:
        # Retain only an aggregate of the digest-only enrollment, never its contents.
        code = (
            "from pathlib import Path; from closure_engine.protocol import strict_loads,digest; "
            "print(digest(strict_loads(Path('/auth/credentials.json').read_bytes())))"
        )
        baseline = subprocess.check_output(
            mount + ["--entrypoint", "python", "agentic-closure-engine:0.3.0", "-I", "-c", code], text=True
        ).strip()
        first = command(
            [
                "api-credential",
                "--credentials",
                "/auth",
                "--principal",
                "haiku-rotation-proof",
                "--role",
                "viewer",
                "--token-out",
                "/export/first.token",
            ]
        )
        issued.append(first["token_sha256"])
        first_token = (private / "first.token").read_text().strip()
        assert request(first_token)["state"] == "ACCEPTED"
        denied = request(first_token, method="POST", action="/approve", expected=403)
        assert denied["error"] == "ROLE_REQUIRED" and denied["role"] == "owner", denied
        second = command(
            [
                "api-credential",
                "--credentials",
                "/auth",
                "--principal",
                "haiku-rotation-proof",
                "--role",
                "viewer",
                "--token-out",
                "/export/second.token",
            ]
        )
        issued.append(second["token_sha256"])
        second_token = (private / "second.token").read_text().strip()
        assert request(second_token)["state"] == "ACCEPTED"
        revoke(first["token_sha256"])
        request(first_token, expected=401)
        assert request(second_token)["state"] == "ACCEPTED"
        if args.restart:
            restarted = subprocess.run(
                ["powershell", "-NoProfile", "-File", "tools/start-product.ps1"],
                capture_output=True,
                text=True,
                timeout=180,
            )
            assert restarted.returncode == 0, {
                "exit": restarted.returncode,
                "error": restarted.stderr[-1000:],
            }
            observations.append({"command": "start-product.ps1", "exit": 0})
            request(first_token, expected=401)
            assert request(second_token)["state"] == "ACCEPTED"
        revoke(second["token_sha256"])
        request(second_token, expected=401)
        # Existing operator credentials remain valid after the temporary enrollment.
        assert request(Path(".runtime/operator.token").read_text().strip())["state"] == "ACCEPTED"
        after = subprocess.check_output(
            mount + ["--entrypoint", "python", "agentic-closure-engine:0.3.0", "-I", "-c", code], text=True
        ).strip()
        assert after == baseline, "Temporary enrollment changed another identity"
        result = {
            "result": "Worked",
            "principal": "haiku-rotation-proof",
            "role": "viewer",
            "uid": 11007,
            "docker_configuration_inspected": False,
            "service_restarts": int(args.restart),
            "existing_enrollment_preserved": True,
            "observations": observations,
        }
    except BaseException as exc:
        (out / "receipt.json").write_text(
            json.dumps({"result": "Failed", "error": str(exc), "observations": observations}, indent=2)
        )
        raise
    finally:
        for digest in issued:
            if digest not in revoked:
                revoke(digest)
        for name in ("first.token", "second.token"):
            (private / name).unlink(missing_ok=True)
    (out / "receipt.json").write_text(json.dumps(result, indent=2))
    print(
        json.dumps(
            {
                "result": "Worked",
                "scope": "Temporary viewer only; previous inspection remains blocked",
                "receipt": str(out / "receipt.json"),
            }
        )
    )


if __name__ == "__main__":
    main()
