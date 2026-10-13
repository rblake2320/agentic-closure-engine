"""Read public runtime history, clone without keys, and exercise warm/cold physical mutations.

Run with an installed interpreter and an independently supplied enrollment hash. All
mutations are confined to a NEW output directory; the original history is read-only.
"""

import argparse
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path

from closure_engine.crypto import TrustStore
from closure_engine.ledger import Ledger
from closure_engine.protocol import ClosureError, canonical, digest, milliseconds, strict_loads, timestamp
from closure_engine.store import EvidenceStore


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def refused(operation):
    try:
        operation()
    except ClosureError as exc:
        return exc.code
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--expected-trust-hash", required=True)
    parser.add_argument("--prior-state", help="Own earlier public ledger for rollback control")
    args = parser.parse_args()
    source, out = Path(args.state).resolve(), Path(args.out).resolve()
    if out.exists() or out == source or source.is_relative_to(out):
        raise ValueError("NEW_SEPARATE_OUTPUT_REQUIRED")
    out.mkdir(parents=True)
    cases = ["truncate", "unsigned-rehash", "event-id", "approval", "raw", "inputs", "evaluator", "baseline"]
    if args.prior_state:
        cases.append("rollback")
    write(
        out / "registered.json",
        {
            "registered_at_ms": int(time.time() * 1000),
            "source": str(source),
            "cases": cases,
            "expected": "Every mutation refused warm and cold; exact byte restoration works",
            "scope": "Public-only private clone; no role keys copied; full audit agrees with warm context",
        },
    )
    custody = source / "authority/custodian"
    trust_raw = (source / "authority/operator/trust.json").read_bytes()
    trust = TrustStore.from_dict(strict_loads(trust_raw))
    if trust.hash != args.expected_trust_hash:
        raise ClosureError("TRUST_ANCHOR_MISMATCH")
    checkpoint = strict_loads((custody / "checkpoint.json").read_bytes())
    target = out / "public-custody"
    target.mkdir()
    for name in ("ledger.sqlite", "checkpoint.json"):
        shutil.copyfile(custody / name, target / name)
    shutil.copytree(custody / "evidence", target / "evidence")
    (target / "trust.json").write_bytes(trust_raw)
    db_path = target / "ledger.sqlite"
    db_original = db_path.read_bytes()

    def open_ledger():
        return Ledger(
            db_path,
            trust,
            EvidenceStore(target / "evidence", create=False),
            checkpoint,
            _require_evaluator_custody=True,
        )

    ledger = open_ledger()
    warm = ledger.snapshot()
    full = ledger.summary(checkpoint)
    assert (warm["head"], warm["sequence"], warm["transactions"]) == (
        full["verified_head"],
        full["sequence"],
        full["transactions"],
    )
    with sqlite3.connect(db_path) as db:
        event = strict_loads(db.execute("SELECT envelope FROM events WHERE sequence=1").fetchone()[0])
        all_events = [
            strict_loads(raw) for (raw,) in db.execute("SELECT envelope FROM events ORDER BY sequence")
        ]
        baseline_event = next(e for e in all_events if e["payload"]["body"]["state"] == "BASELINED")
    packet = next(iter(warm["packets"].values()))["payload"]["body"]
    inputs = strict_loads(ledger.store.get(packet["inputs_hash"]))
    manifest = strict_loads(ledger.store.get(baseline_event["payload"]["body"]["refs"][0]))
    references = {
        "raw": inputs["records"][0]["observation"]["payload"]["body"]["evidence_hash"],
        "inputs": packet["inputs_hash"],
        "evaluator": packet["evaluator_hash"],
        "baseline": manifest["artifact_hash"],
    }
    results = []
    for case in cases:
        assert ledger.snapshot() == warm
        path = db_path if case not in references else ledger.store.path_for(references[case])
        original, stat = path.read_bytes(), path.stat()
        if case in references:
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        elif case == "rollback":
            previous = Path(args.prior_state).resolve() / "authority/custodian/ledger.sqlite"
            path.write_bytes(previous.read_bytes())
        else:
            with sqlite3.connect(db_path) as db:
                if case == "truncate":
                    db.execute("DELETE FROM events WHERE sequence=(SELECT MAX(sequence) FROM events)")
                elif case == "unsigned-rehash":
                    altered = json.loads(json.dumps(event))
                    altered["payload"]["created_at"] = timestamp(
                        milliseconds(event["payload"]["created_at"]) + 1
                    )
                    db.execute(
                        "UPDATE events SET envelope=?,event_hash=? WHERE sequence=1",
                        (canonical(altered), digest(altered)),
                    )
                elif case == "event-id":
                    db.execute("UPDATE events SET event_id='changed-storage-id' WHERE sequence=1")
                else:
                    tx, raw = db.execute("SELECT transaction_id,approval FROM contracts LIMIT 1").fetchone()
                    approval = strict_loads(raw)
                    approval["signature"] = "00" * 64
                    db.execute(
                        "UPDATE contracts SET approval=? WHERE transaction_id=?", (canonical(approval), tx)
                    )
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        try:
            warm_code = refused(ledger.snapshot)
            cold_code = refused(open_ledger)
            assert warm_code is not None and cold_code is not None, (case, warm_code, cold_code)
            results.append(
                {
                    "case": case,
                    "warm_refusal": warm_code,
                    "cold_refusal": cold_code,
                    "same_size": path.stat().st_size == stat.st_size,
                    "same_mtime": path.stat().st_mtime_ns == stat.st_mtime_ns,
                }
            )
        finally:
            path.write_bytes(original)
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        assert ledger.snapshot() == warm and open_ledger().snapshot() == warm
        write(out / "cases.json", results)
    assert db_path.read_bytes() == db_original
    receipt = {
        "status": "Worked",
        "cases": results,
        "sequence": warm["sequence"],
        "transactions": len(warm["transactions"]),
        "head": warm["head"],
        "native_full_agreement": True,
        "restoration_controls": len(results),
        "public_only_clone": True,
        "shared_cache": ledger.store.verification_cache_info(),
    }
    write(out / "receipt.json", receipt)
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
