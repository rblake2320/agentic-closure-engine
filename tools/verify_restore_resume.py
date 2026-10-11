"""Exercise a real failed ownership operation, startup refusal and same-archive resume in Docker."""

import argparse
import json
import secrets
import subprocess
from pathlib import Path

VOLUMES = {
    "actor-key": "keys/actor",
    "owner-key": "keys/owner",
    "authority-key": "keys/authority",
    "verifier-key": "keys/verifier",
    "broker-key": "keys/broker",
    "operator": "operator",
    "actor-auth": "auth/actor",
    "owner-auth": "auth/owner",
    "authority-auth": "auth/authority",
    "verifier-auth": "auth/verifier",
    "broker-auth": "auth/broker",
    "custody-auth": "custody-auth",
    "custody-data": "custody-data",
    "broker-intents": "broker-intents",
    "gateway-data": "gateway",
    "gateway-auth": "gateway-auth",
    "publisher-data": "publisher-data",
    "export-data": "exports",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--trust-hash", required=True)
    parser.add_argument("--expected-archive-hash", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    prefix = "ace-resume-check-" + secrets.token_hex(5)
    base = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges:true",
        "--env",
        "TMPDIR=/scratch",
        "--tmpfs",
        "/scratch:rw,noexec,nosuid,size=1g,mode=700",
    ]
    for volume, relative in VOLUMES.items():
        base += ["--mount", f"type=volume,source={prefix}_{volume},target=/volumes/{relative}"]
    base += [
        "--mount",
        f"type=bind,source={Path(args.backup).resolve()},target=/backup,readonly",
        "--mount",
        f"type=bind,source={Path(args.key_file).resolve()},target=/backup-key/snapshot.key,readonly",
        "--mount",
        f"type=bind,source={Path(args.checkpoint).resolve()},target=/anchor/checkpoint.json,readonly",
        "--mount",
        f"type=bind,source={Path(args.profile).resolve()},target=/profile.json,readonly",
    ]
    observations = []

    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        observations.append(
            {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        )
        return result

    wrong = run(base + ["agentic-closure-engine:0.3.0", "restore", args.trust_hash, "0" * 64])
    assert wrong.returncode == 2 and "RESTORE_ARCHIVE_DIGEST_MISMATCH" in wrong.stdout
    empty = run(
        base
        + [
            "--entrypoint",
            "python",
            "agentic-closure-engine:0.3.0",
            "-I",
            "-c",
            "from pathlib import Path; "
            "assert not any(p.is_file() for p in Path('/volumes').rglob('*')); "
            "print('NO_INSTALLATION_FILES')",
        ]
    )
    assert empty.returncode == 0 and "NO_INSTALLATION_FILES" in empty.stdout
    first = run(
        base + ["agentic-closure-engine:0.3.0", "restore", args.trust_hash, args.expected_archive_hash]
    )
    assert first.returncode == 2 and "BACKUP_STORAGE_ERROR" in first.stdout, first.stderr
    check = (
        "from closure_engine.runtime.container_bootstrap import provision; "
        "provision('/volumes','/profile.json')"
    )
    blocked = run(base + ["--entrypoint", "python", "agentic-closure-engine:0.3.0", "-I", "-c", check])
    assert blocked.returncode != 0 and "RESTORE_INCOMPLETE" in blocked.stderr, blocked.stderr
    complete = run(
        base
        + [
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "agentic-closure-engine:0.3.0",
            "restore",
            args.trust_hash,
            args.expected_archive_hash,
        ]
    )
    assert complete.returncode == 0 and json.loads(complete.stdout)["result"] == "Worked", complete.stderr
    again = run(
        base
        + [
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "agentic-closure-engine:0.3.0",
            "restore",
            args.trust_hash,
            args.expected_archive_hash,
        ]
    )
    assert again.returncode == 0 and json.loads(again.stdout)["result"] == "AlreadyRestored", again.stderr
    Path(args.output).write_text(
        json.dumps({"result": "Worked", "prefix": prefix, "cases": 6, "observations": observations}, indent=2)
    )
    print(json.dumps({"result": "Worked", "cases": 6, "receipt": args.output, "volumes_retained": prefix}))


if __name__ == "__main__":
    main()
