import pytest
from test_ledger import begin, event, packet
from test_recovery import child_packet

from closure_engine.crypto import sign
from closure_engine.protocol import digest, timestamp


@pytest.mark.parametrize(("fail", "state"), [(False, "RECOVERED"), (True, "RECOVERY_FAILED")])
def test_recovery_ledger_state_and_original_verdict(run, tmp_path, fail, state):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    ledger.append(event(run, ledger, "OBSERVING", packet=packet(run, ledger, now=run["start"])), ledger.head)
    parent = packet(run, ledger)
    ledger.append(event(run, ledger, "PROVEN", packet=parent), ledger.head)
    ledger.append(event(run, ledger, "RECOVERY_REQUIRED"), ledger.head)
    frozen, child = child_packet(run, parent, fail=fail)
    e = event(
        run, ledger, state, packet=child, recovery_contract=frozen.data, recovery_approval=frozen.approval
    )
    e = sign(
        run["keys"]["authority"], "ledger-event", e["payload"]["body"], timestamp(run["start"] + 120_000)
    )
    ledger.append(e, ledger.head)
    assert ledger.state("transaction-1") == state
    assert digest(ledger.technical_packet("transaction-1")) == digest(parent)
    for name, value in [("parent-packet", parent), ("recovery-packet", child), ("trust", run["trust"].data)]:
        from closure_engine.protocol import canonical

        (tmp_path / (name + ".json")).write_bytes(canonical(value))
