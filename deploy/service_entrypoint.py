"""Container command adapter: mount-owned trust pin and fixed service identity."""

import json
import os
import sys
from importlib.resources import files
from pathlib import Path

from closure_engine.cli import main
from closure_engine.protocol import ClosureError
from closure_engine.runtime.files import read_json

mode = sys.argv[1]
if mode in {"backup", "restore"}:
    from closure_engine.runtime.container_backup import backup, restore

    expected_pin = sys.argv[2]
    try:
        result = (
            backup("/volumes", "/backup", expected_pin, "/backup-key/snapshot.key")
            if mode == "backup"
            else restore(
                "/volumes",
                "/backup/snapshot.ace",
                "/backup-key/snapshot.key",
                expected_pin,
                read_json("/anchor/checkpoint.json", "RESTORE_CHECKPOINT_REQUIRED"),
            )
        )
    except ClosureError as exc:
        print(json.dumps({"error": exc.code, "detail": str(exc)}))
        raise SystemExit(2)
    except OSError as exc:
        print(json.dumps({"error": "BACKUP_STORAGE_ERROR", "type": type(exc).__name__}))
        raise SystemExit(2)
    print(json.dumps(result))
    raise SystemExit(0)
if mode == "bootstrap":
    from closure_engine.runtime.container_bootstrap import provision

    result = provision("/volumes", "/input/target-profile.json")
    artifact = Path("/input/initial-artifact.json")
    if artifact.is_file():
        from closure_engine.runtime.container_bootstrap import _ownership
        from closure_engine.runtime.target import ReferenceTarget

        state = Path("/volumes/publisher-data")
        if not (state / "state.json").exists():
            ReferenceTarget.initialize(state, artifact.read_bytes(), result["target_deploy_token_sha256"])
        target = ReferenceTarget(state)
        if target.meta["token_sha256"] != result["target_deploy_token_sha256"]:
            raise SystemExit("Publisher credential does not match its enrollment")
        _ownership(state, 11008)
    print(json.dumps(result))
    raise SystemExit(0)
if mode == "publisher":
    from closure_engine.runtime.target import ReferenceTargetServer

    server = ReferenceTargetServer(("0.0.0.0", 9002), "/publisher")
    server.serve_forever()
if mode == "gateway":
    public_port = str(int(os.environ.get("ACE_PUBLIC_PORT", "8782")))
    raise SystemExit(
        main(
            [
                "api-serve",
                "--services",
                "/gateway/services.json",
                "--credentials",
                "/gateway-auth",
                "--bind",
                "0.0.0.0",
                "--port",
                "8782",
                "--allowed-host",
                "127.0.0.1:" + public_port,
                "--allowed-host",
                "localhost:" + public_port,
                "--allowed-host",
                "gateway:8782",
                "--static-dir",
                str(files("closure_engine").joinpath("web")),
            ]
        )
    )
pin = Path("/state/operator/trust.pin").read_text().strip()
arguments = [
    "--deployment",
    "/state",
    "--expected-trust-hash",
    pin,
    "--bind",
    "0.0.0.0",
    "--credentials",
    "/auth",
]
if mode == "custody":
    raise SystemExit(main(["custody-serve", *arguments, "--port", "9000", "--allowed-host", "custody:9000"]))
if mode not in {"actor", "owner", "authority", "verifier", "broker"}:
    raise SystemExit("Unknown service role")
raise SystemExit(
    main(
        [
            "role-serve",
            *arguments,
            "--role",
            mode,
            "--port",
            "9001",
            "--allowed-host",
            mode + ":9001",
            "--custody-url",
            "http://custody:9000",
            "--custody-token-file",
            "/state/" + mode + "/custody.token",
        ]
    )
)
