"""O-09 probes (scratch, not committed). Each asserts a monotonic/trusted-time boundary;
red means the ledger accepts signer-chosen time."""

import pytest
from test_ledger import begin, event, packet

from closure_engine.crypto import sign
from closure_engine.protocol import ClosureError, timestamp


def resign(run, e, role, at):
    return sign(run["keys"][role], "ledger-event", e["payload"]["body"], timestamp(at))


def proven_ledger(run, tmp_path):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    ledger.append(event(run, ledger, "OBSERVING", packet=packet(run, ledger, now=run["start"])), ledger.head)
    return ledger


# P1: an event may not be dated before its predecessor.
def test_P1_control_monotonic_event_time_accepted(run, tmp_path):
    ledger = proven_ledger(run, tmp_path)
    e = resign(
        run, event(run, ledger, "PROVEN", packet=packet(run, ledger)), "authority", run["start"] + 60_000
    )
    ledger.append(e, ledger.head)


def test_P1_event_time_cannot_regress(run, tmp_path):
    ledger = proven_ledger(run, tmp_path)
    e = resign(
        run, event(run, ledger, "PROVEN", packet=packet(run, ledger)), "authority", run["start"] - 86_400_000
    )
    with pytest.raises(ClosureError):
        ledger.append(e, ledger.head)


# P2: the verdict packet's evaluation time may not precede an already ledgered evaluation.
def test_P2_verdict_evaluation_cannot_precede_ledgered_observation_packet(run, tmp_path):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    ledger.append(
        event(run, ledger, "OBSERVING", packet=packet(run, ledger, now=run["start"] + 60_000)), ledger.head
    )
    earlier = packet(run, ledger, now=run["start"] + 30_000)
    assert earlier["payload"]["body"]["verdict"] == "INDETERMINATE"
    with pytest.raises(ClosureError):
        ledger.append(event(run, ledger, "INDETERMINATE", packet=earlier), ledger.head)
