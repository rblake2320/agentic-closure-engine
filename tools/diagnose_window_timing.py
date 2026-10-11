"""Diagnostic receipt for window-coverage timing (CI failure 735a1d3, recovery child INDETERMINATE).

Runs the real recovery scenario (reference target over loopback HTTP, persistent keys, real
ledger) on the installed package, optionally with CPU burner processes to emulate a loaded CI
runner, and records from public signed data only: binding window_start, every observation's
observed_at and result, step durations, ledger length, and the packet's checks/rejections.

Usage: python -I tools/diagnose_window_timing.py --output receipt.json [--burners N] [--settle-ms 2500]
"""

import argparse
import json
import multiprocessing
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path


def burn(stop_at):
    x = 0
    while time.time() < stop_at:
        x = (x * 1103515245 + 12345) % 2**31


def artifact(answer, other="stable"):
    routes = {"/answer": {"answer": answer}, "/config": {"mode": "safe"}, "/other": {"value": other}}
    return json.dumps({"routes": routes}, sort_keys=True).encode()


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
        "probe": {"type": "artifact-bytes"},
    },
    {
        "id": "baseline",
        "kind": "baseline",
        "phase": "instant",
        "mandatory": True,
        "probe": {"type": "baseline-custody"},
    },
]


def timeline(runtime, tx, steps):
    from closure_engine.protocol import milliseconds

    meta = runtime._tx(tx)
    binding = meta["binding"]
    body = binding["payload"]["body"]
    start = milliseconds(body["window_start"])
    window = meta["contract"]["window"]
    records = runtime.custody.records(tx)
    samples = sorted(
        (
            r["observation"]["payload"]["body"]["check_id"],
            r["observation"]["payload"]["body"]["phase"],
            milliseconds(r["observation"]["payload"]["body"]["observed_at"]) - start,
            r["observation"]["payload"]["body"]["result"],
        )
        for r in records
    )
    packet = meta.get("verdict_packet")
    pbody = packet["payload"]["body"] if packet else {}
    return {
        "transaction_id": tx,
        "binding_created_minus_window_start_ms": milliseconds(binding["payload"]["created_at"]) - start,
        "window": window,
        "first_sample_tolerance_ms": window["max_clock_skew_ms"],
        "samples_ms_relative_to_window_start": [
            {"check": c, "phase": p, "offset_ms": o, "result": r} for c, p, o, r in samples
        ],
        "late_first_window_sample": any(
            p == "window" and o > window["max_clock_skew_ms"]
            for c, p, o, r in samples
            if o == min(x[2] for x in samples if x[0] == c)
        ),
        "verdict": pbody.get("verdict"),
        "reason_codes": pbody.get("reason_codes"),
        "checks": pbody.get("checks"),
        "rejected": pbody.get("rejected"),
        "window_complete": pbody.get("window_complete"),
        "steps_ms": steps,
    }


def timed(steps, name, fn, *args, **kwargs):
    import cProfile
    import io
    import pstats

    profiler = cProfile.Profile()
    t0 = time.perf_counter()
    profiler.enable()
    try:
        result = fn(*args, **kwargs)
    finally:
        profiler.disable()
    elapsed = round((time.perf_counter() - t0) * 1000)
    entry = {"step": name, "ms": elapsed}
    if elapsed > 2000:
        out = io.StringIO()
        pstats.Stats(profiler, stream=out).sort_stats("cumulative").print_stats(12)
        entry["profile_top"] = [line.strip() for line in out.getvalue().splitlines() if "(" in line][:14]
    steps.append(entry)
    return result


def lifecycle(runtime, tx, steps, propose=None):
    if propose is not None:
        timed(steps, "propose", propose)
    for step in ("approve", "freeze", "baseline", "bind"):
        timed(steps, step, getattr(runtime, step), tx)
    deployed = timed(steps, "deploy", runtime.deploy, tx)
    steps.append({"step": "deploy-result", "value": deployed})
    timed(steps, "observe(all)", runtime.observe, tx, phase="all")
    result = timed(steps, "close", runtime.close, tx)
    if result["state"] == "OBSERVING":
        result = timed(steps, "close-final", runtime.close, tx)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--burners", type=int, default=0)
    parser.add_argument("--settle-ms", type=int, default=2500)
    parser.add_argument("--duration-ms", type=int, default=3000)
    parser.add_argument("--skew-ms", type=int, default=1000)
    args = parser.parse_args()

    import closure_engine
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

    stop_at = time.time() + 600
    burners = [
        multiprocessing.Process(target=burn, args=(stop_at,), daemon=True) for _ in range(args.burners)
    ]
    for p in burners:
        p.start()
    work = Path(tempfile.mkdtemp(prefix="ace-diag-"))
    deployment = Deployment(work / "ace")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-diag")
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{port}", CHECKS)
    ReferenceTarget.initialize(work / "target", artifact(1), target["deploy_token_sha256"])
    server = ReferenceTargetServer(("127.0.0.1", port), work / "target")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    runtime = Runtime(deployment, pin)
    options = dict(
        duration_ms=args.duration_ms, min_samples=3, max_clock_skew_ms=args.skew_ms, settle_ms=args.settle_ms
    )
    parent_steps, child_steps = [], []
    lifecycle(
        runtime,
        "tx-bad",
        parent_steps,
        lambda: runtime.propose(
            "shop/api",
            "tx-bad",
            artifact(3, other="CHANGED"),
            intent="diag",
            expect={"primary": 3},
            **options,
        ),
    )
    runtime.begin_recovery("tx-bad")
    child = lifecycle(runtime, "tx-bad/recovery", child_steps)
    receipt = {
        "package": closure_engine.__file__,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "cpu_count": os.cpu_count(),
        "burners": args.burners,
        "settings": options,
        "ledger_events": runtime.custody.summary()["sequence"],
        "parent": timeline(runtime, "tx-bad", parent_steps),
        "child": timeline(runtime, "tx-bad/recovery", child_steps),
        "child_verdict": child.get("verdict"),
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True))
    print(
        json.dumps(
            {
                "child_verdict": receipt["child_verdict"],
                "late": receipt["child"]["late_first_window_sample"],
                "ledger_events": receipt["ledger_events"],
            }
        )
    )
    server.shutdown()
    for p in burners:
        p.terminate()


if __name__ == "__main__":
    main()
