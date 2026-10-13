"""Measure the actual installed Runtime at a frozen 3s/min3 no-fault release workload.

The control is unprofiled. cProfile runs afterward against real checkpointed Ledger reads and
an exact idempotent event retry, so profiling overhead cannot cause the control's sample loss.
Fresh and continuation processes retain the same own-created history and target profile.
"""

import argparse
import cProfile
import hashlib
import io
import json
import platform
import pstats
import secrets
import socket
import threading
import time
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from closure_engine.protocol import digest, milliseconds
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
from closure_engine.runtime.custody import LocalCustody
from closure_engine.runtime.custody_service import CustodyServer, RemoteCustody

WINDOW = {"duration_ms": 3000, "min_samples": 3, "max_clock_skew_ms": 1000, "settle_ms": 2500}
CHECKS = [
    {
        "id": "primary",
        "kind": "primary",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "http-json", "path": "/answer", "pointer": "/answer"},
    },
    *(
        {
            "id": "protected-" + name,
            "kind": "invariant",
            "phase": "window",
            "mandatory": True,
            "probe": {"type": "http-unchanged", "path": "/" + path},
        }
        for name, path in (("config", "config"), ("other", "other"))
    ),
    *(
        {"id": name, "kind": name, "phase": "instant", "mandatory": True, "probe": {"type": probe}}
        for name, probe in (
            ("deployment", "active-artifact"),
            ("stage", "staged-artifact"),
            ("baseline", "baseline-custody"),
        )
    ),
]


def artifact(answer):
    return json.dumps(
        {
            "routes": {
                "/answer": {"answer": answer},
                "/config": {"mode": "safe"},
                "/other": {"value": "stable"},
            }
        },
        sort_keys=True,
    ).encode()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding="utf-8")


def initialize(root):
    deployment = Deployment(root / "authority")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "history-" + role)
    pin = enroll(deployment, [item["id"] for item in CHECKS])["trust_hash"]
    (root / "independent-trust.pin").write_text(pin)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    profile = enroll_target(deployment, "history-control", f"http://127.0.0.1:{port}", CHECKS)
    ReferenceTarget.initialize(root / "target", artifact(0), profile["deploy_token_sha256"])
    return deployment, pin


def timed(records, name, operation):
    start, cpu = time.perf_counter(), time.process_time()
    value = operation()
    records[name] = {
        "wall_ms": (time.perf_counter() - start) * 1000,
        "cpu_ms": (time.process_time() - cpu) * 1000,
    }
    return value


def sample_report(runtime, tx):
    meta = runtime.custody.tx(tx)
    start = milliseconds(meta["binding"]["payload"]["body"]["window_start"])
    records = runtime.custody.records(tx)
    by_check = {}
    for record in records:
        body = record["observation"]["payload"]["body"]
        if body["phase"] != "window":
            continue
        by_check.setdefault(body["check_id"], []).append(
            {
                "offset_ms": milliseconds(body["observed_at"]) - start,
                "result": body["result"],
                "id": body["observation_id"],
            }
        )
    for entries in by_check.values():
        entries.sort(key=lambda item: item["offset_ms"])
    return {"window_start": start, "window": meta["contract"]["window"], "samples": by_check}


def snapshot_profile(local, output):
    profile = cProfile.Profile()
    profile.enable()
    before = local.ledger.snapshot()
    profile.disable()
    profile.dump_stats(str(output / "snapshot.pstats"))
    stream = io.StringIO()
    pstats.Stats(profile, stream=stream).sort_stats("cumulative").print_stats(45)
    (output / "snapshot-profile.txt").write_text(stream.getvalue(), encoding="utf-8")
    export = local.ledger.audit_export(1, 1000)
    last = export["events"][-1]
    retry = cProfile.Profile()
    retry.enable()
    returned = local.ledger.append(last, before["head"])
    retry.disable()
    retry.dump_stats(str(output / "idempotent-append.pstats"))
    stream = io.StringIO()
    pstats.Stats(retry, stream=stream).sort_stats("cumulative").print_stats(45)
    (output / "idempotent-append-profile.txt").write_text(stream.getvalue(), encoding="utf-8")
    after = local.ledger.snapshot()
    assert before == after and returned == digest(last)
    return {"head": before["head"], "sequence": before["sequence"], "exact_retry_preserved_state": True}


def execute(args):
    output = Path(args.out).absolute()
    if output.exists():
        raise ValueError("NEW_REPORT_DIRECTORY_REQUIRED")
    output.mkdir(parents=True)
    root = Path(args.state).absolute() if args.state else output / "state"
    registration = {
        "registered_at_ms": int(time.time() * 1000),
        "package_version": version("agentic-closure-engine"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "count": args.count,
        "stop_after_failures": args.stop_after_failures,
        "window": WINDOW,
        "faults": [],
        "custody_mode": "real-loopback-RPC" if args.custody_rpc else "local",
        "state": str(root),
        "expectation": (
            "Every no-fault correctly deployed release PROVEN with unchanged3s/min3/gap1500 criteria; "
            "failed verdict retained, never excused by profile or larger window"
        ),
    }
    write(output / "registered-control.json", registration)
    if args.state:
        deployment = Deployment(root / "authority")
        pin = (root / "independent-trust.pin").read_text().strip()
    else:
        root.mkdir()
        deployment, pin = initialize(root)
    trust = deployment.load_trust(pin)
    profile = deployment.target("history-control")
    target = ReferenceTargetServer(("127.0.0.1", urlsplit(profile["base_url"]).port), root / "target")
    local = LocalCustody(deployment, trust, Runtime(deployment, pin).clock)
    servers = [target]
    if args.custody_rpc:
        token = secrets.token_urlsafe(32)
        credentials = {
            hashlib.sha256(token.encode()).hexdigest(): {
                "principal": "profile-runtime",
                "roles": ["actor", "owner", "authority", "verifier", "broker", "operator", "custodian"],
            }
        }
        custody = CustodyServer(("127.0.0.1", 0), local, hosts=None, credentials=credentials)
        servers.append(custody)
        runtime = Runtime(
            deployment, pin, custody=RemoteCustody(f"http://127.0.0.1:{custody.server_port}", token)
        )
    else:
        runtime = Runtime(deployment, pin, custody=local)
    server_threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        server_threads.append(thread)
    servers_stopped = False

    def stop_servers():
        nonlocal servers_stopped
        if servers_stopped:
            return
        for server in reversed(servers):
            server.shutdown()
            server.server_close()
        for thread in server_threads:
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("OWNED_SERVER_THREAD_DID_NOT_STOP")
        servers_stopped = True

    results, failures = [], 0
    current = json.loads(target.target.raw)["routes"]["/answer"]["answer"]
    try:
        for index in range(args.count):
            answer = current + index + 1
            tx = f"history-{answer}"
            steps = {}
            began = time.perf_counter()
            timed(
                steps,
                "propose",
                lambda: runtime.propose(
                    "history-control",
                    tx,
                    artifact(answer),
                    intent="Advance approved answer; preserve both protected resources",
                    expect={"primary": answer},
                    **WINDOW,
                ),
            )
            for action in ("approve", "freeze", "baseline", "bind", "deploy", "observe", "close"):
                result = timed(steps, action, lambda action=action: getattr(runtime, action)(tx))
            if result["state"] == "OBSERVING":
                result = timed(steps, "final_close", lambda: runtime.close(tx))
            if result["verdict"] == "PROVEN":
                timed(steps, "accept", lambda: runtime.accept(tx))
            else:
                failures += 1
            elapsed = (time.perf_counter() - began) * 1000
            entry = {
                "transaction": tx,
                "index": index,
                "elapsed_ms": elapsed,
                "verdict": result["verdict"],
                "state": result["state"],
                "checks": result["checks"],
                "reasons": result["reason_codes"],
                "steps": steps,
                "qualified_sample_clock": sample_report(runtime, tx),
            }
            results.append(entry)
            with (output / "releases.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry) + "\n")
            print(
                json.dumps({"index": index, "verdict": result["verdict"], "wall_ms": round(elapsed, 1)}),
                flush=True,
            )
            if args.stop_after_failures and failures >= args.stop_after_failures:
                break
        # cProfile's monitoring can see another thread's waits on recent Python versions.
        # No service thread remains before the separate read-only CPU profile begins.
        stop_servers()
        profile_result = snapshot_profile(local, output) if args.profile else None
        receipt = {
            "status": "Failed" if failures else "Worked",
            "registered": registration,
            "executed": len(results),
            "proven": len(results) - failures,
            "non_proven": failures,
            "profile": profile_result,
            "first_failure": next((entry for entry in results if entry["verdict"] != "PROVEN"), None),
            "own_servers_stopped": servers_stopped,
        }
        write(output / "receipt.json", receipt)
        return receipt
    finally:
        stop_servers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--state", help="Continue exact own-created saved state and enrolled target port")
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--stop-after-failures", type=int, default=2)
    parser.add_argument("--custody-rpc", action="store_true")
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.count <= 1000 or not 0 <= args.stop_after_failures <= args.count:
        parser.error("bounded count1..1000 and stop-after-failures0..count required")
    result = execute(args)
    print(
        json.dumps(
            {
                "status": result["status"],
                "executed": result["executed"],
                "proven": result["proven"],
                "non_proven": result["non_proven"],
            }
        )
    )


if __name__ == "__main__":
    main()
