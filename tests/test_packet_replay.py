import copy

import pytest
from test_ledger import begin, event, packet

from closure_engine.crypto import sign
from closure_engine.protocol import ClosureError, timestamp
from closure_engine.verdicts import replay_packet


def test_signed_fabricated_success_must_be_replayed(run, tmp_path):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    immediate = packet(run, ledger, now=run["start"])
    ledger.append(event(run, ledger, "OBSERVING", packet=immediate), ledger.head)
    result = packet(run, ledger, records=[])
    body = copy.deepcopy(result["payload"]["body"])
    body.update(verdict="PROVEN", reason_codes=[], recovery_required=False)
    body["checks"] = {check["id"]: "PASS" for check in run["contract"]["checks"]}
    fabricated = sign(run["keys"]["authority"], "closure-packet", body, timestamp(run["start"] + 60000))
    with pytest.raises(ClosureError, match="PACKET_REPLAY_MISMATCH"):
        ledger.append(event(run, ledger, "PROVEN", packet=fabricated), ledger.head)
    assert ledger.state("transaction-1") == "OBSERVING"


def test_packet_replay_valid_control_without_signing_key(run, tmp_path):
    ledger = begin(run, tmp_path)
    signed = packet(run, ledger)
    assert replay_packet(signed, run["store"], run["trust"])["verdict"] == "PROVEN"


@pytest.mark.parametrize("field,value", [("admitted", []), ("rejected", []),
                                        ("reason_codes", ["INVENTED_REASON"]),
                                        ("window_end", "2026-10-11T12:02:00Z")])
def test_packet_replay_checks_all_claims(run, tmp_path, field, value):
    ledger = begin(run, tmp_path)
    signed = packet(run, ledger, records=[])
    body = copy.deepcopy(signed["payload"]["body"])
    if body[field] == value:
        body[field] = ["sha256:" + "0" * 64] if field == "admitted" else [{
            "hash": "sha256:" + "0" * 64, "reason": "INVENTED_REASON"
        }]
    else:
        body[field] = value
    altered = sign(run["keys"]["authority"], "closure-packet", body, signed["payload"]["created_at"])
    with pytest.raises(ClosureError, match="PACKET_REPLAY_MISMATCH"):
        replay_packet(altered, run["store"], run["trust"])
