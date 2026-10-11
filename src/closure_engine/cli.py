"""Bounded offline CLI. There are no credential discovery or deployment commands."""

import argparse
import hmac
import json
import re
import sys
from pathlib import Path

from .contracts import freeze
from .crypto import TrustStore
from .demo import SCENARIOS, demo
from .ledger import Ledger
from .protocol import MAX_BYTES, ClosureError, milliseconds, strict_loads
from .store import EvidenceStore
from .verdicts import evaluate, replay_packet

TRUST_ANCHOR = re.compile(r"sha256:[0-9a-f]{64}")
PIN_HELP = "Operator-held sha256 of the canonical enrollment snapshot; never read from --trust's folder"


def read_json(path):
    with Path(path).open("rb") as stream:
        return strict_loads(stream.read(MAX_BYTES + 1))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline deterministic closure kernel")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("demo", help="Synthetic deployment fixture; real local crypto/artifact/ledger I/O")
    p.add_argument("--output", required=True)
    p.add_argument("--scenario", choices=SCENARIOS, default="valid")
    p = sub.add_parser("evaluate-run", help="Recompute a verdict; public trust is operator-supplied")
    p.add_argument("--bundle", required=True)
    p.add_argument("--trust", required=True)
    p.add_argument("--expected-trust-hash", required=True, help=PIN_HELP)
    p.add_argument("--store", required=True)
    p.add_argument("--at", required=True, help="Trusted UTC evaluation time, ending in Z")
    p.add_argument("--require-proven", action="store_true")
    p = sub.add_parser("verify-ledger", help="Verify signed history against an independent checkpoint")
    p.add_argument("--ledger", required=True)
    p.add_argument("--trust", required=True)
    p.add_argument("--expected-trust-hash", required=True, help=PIN_HELP)
    p.add_argument("--store", required=True)
    p.add_argument("--checkpoint", required=True)
    p = sub.add_parser("verify-packet", help="Independently replay a signed packet from retained inputs")
    p.add_argument("--packet", required=True)
    p.add_argument("--trust", required=True)
    p.add_argument("--expected-trust-hash", required=True, help=PIN_HELP)
    p.add_argument("--store", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            result = demo(args.output, args.scenario)
        else:
            # Pin the enrollment before any evidence store or ledger is opened.
            if not TRUST_ANCHOR.fullmatch(args.expected_trust_hash):
                raise ClosureError("INVALID_TRUST_ANCHOR")
            trust = TrustStore.from_dict(read_json(args.trust))
            if not hmac.compare_digest(trust.hash, args.expected_trust_hash):
                raise ClosureError("TRUST_ANCHOR_MISMATCH")
            store = EvidenceStore(args.store)
            if args.command == "evaluate-run":
                bundle = read_json(args.bundle)
                if set(bundle) != {"mode", "contract", "approval", "binding", "records", "receipts"}:
                    raise ClosureError("INVALID_RUN_BUNDLE")
                if bundle["mode"] != "offline-fixture":
                    raise ClosureError("UNSUPPORTED_RUNTIME_MODE")
                frozen = freeze(bundle["contract"], bundle["approval"], trust)
                result = evaluate(
                    frozen,
                    bundle["binding"],
                    bundle["records"],
                    bundle["receipts"],
                    store,
                    trust,
                    milliseconds(args.at),
                ).to_dict()
                result["mode"] = bundle["mode"]
            elif args.command == "verify-packet":
                result = replay_packet(read_json(args.packet), store, trust)
            else:
                if not Path(args.ledger).is_file():
                    raise ClosureError("LEDGER_MISSING")
                checkpoint = read_json(args.checkpoint)
                ledger = Ledger(args.ledger, trust, store, checkpoint=checkpoint)
                result = {
                    "verified_head": ledger.verify(checkpoint),
                    "state": ledger.state("fixture-transaction"),
                    "sequence": ledger.sequence,
                }
        print(json.dumps(result, sort_keys=True))
        return (
            3
            if args.command == "evaluate-run" and args.require_proven and (result["verdict"] != "PROVEN")
            else 0
        )
    except ClosureError as exc:
        print(json.dumps({"error": exc.code, "detail": str(exc)}), file=sys.stderr)
        return 2
    except (OSError, KeyError, TypeError) as exc:
        print(json.dumps({"error": "INPUT_OR_STORAGE_ERROR", "type": type(exc).__name__}), file=sys.stderr)
        return 2
