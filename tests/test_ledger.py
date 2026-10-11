import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from closure_engine.crypto import sign
from closure_engine.ledger import Ledger
from closure_engine.protocol import ClosureError, canonical, digest, timestamp
from closure_engine.verdicts import close_run


def event(
    run,
    ledger,
    state,
    *,
    role=None,
    packet=None,
    binding=None,
    receipt=None,
    refs=None,
    event_id=None,
    recovery_contract=None,
    recovery_approval=None,
    risk=None,
):
    roles = {
        "DRAFT": "actor",
        "APPROVED": "owner",
        "BASELINED": "verifier",
        "EXECUTING": "broker",
        "VERIFYING": "broker",
        "ACCEPTED": "owner",
        "RISK_ACCEPTED": "owner",
    }
    role = role or roles.get(state, "authority")
    body = {
        "event_id": event_id or "event-" + state,
        "transaction_id": run["contract"]["transaction_id"],
        "contract_hash": run["frozen"].hash,
        "sequence": ledger.sequence + 1,
        "previous_hash": ledger.head,
        "state": state,
        "refs": refs or [],
        "packet": packet,
        "binding": binding,
        "receipt": receipt,
        "recovery_contract": recovery_contract,
        "recovery_approval": recovery_approval,
        "risk": risk,
    }
    return sign(run["keys"][role], "ledger-event", body, timestamp(run["start"]))


def begin(run, tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite", run["trust"], run["store"])
    ledger.register(run["frozen"])
    for state in ["DRAFT", "APPROVED", "FROZEN"]:
        ledger.append(event(run, ledger, state), ledger.head)
    resources = {
        name: run["store"].put(("baseline " + name).encode())
        for name in run["contract"]["protected_resources"]
    }
    run["store"].put(b"baseline artifact")
    manifest = run["store"].put(canonical({"artifact_hash": run["baseline"], "protected": resources}))
    ledger.append(event(run, ledger, "BASELINED", refs=[manifest]), ledger.head)
    ledger.append(event(run, ledger, "EXECUTING", binding=run["binding"]), ledger.head)
    return ledger


def packet(run, ledger, **changes):
    args = {k: run[k] for k in ["frozen", "binding", "records", "receipts", "store", "trust"]}
    args.update(now=run["start"] + 60_000, authority=run["keys"]["authority"], ledger_head=ledger.head)
    args.update(changes)
    return close_run(**args)


def test_lifecycle_valid_control_and_acceptance(run, tmp_path):
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    immediate = packet(run, ledger, now=run["start"])
    ledger.append(event(run, ledger, "OBSERVING", packet=immediate), ledger.head)
    result = packet(run, ledger)
    ledger.append(event(run, ledger, "PROVEN", packet=result), ledger.head)
    ledger.append(event(run, ledger, "ACCEPTED"), ledger.head)
    assert ledger.state("transaction-1") == "ACCEPTED"
    assert ledger.verify() == ledger.head


@pytest.mark.parametrize("state", ["PROVEN", "RECOVERED", "ACCEPTED", "OBSERVING"])
def test_A21_illegal_transition(run, tmp_path, state):
    ledger = begin(run, tmp_path)
    with pytest.raises(ClosureError):
        ledger.append(event(run, ledger, state), ledger.head)
    assert ledger.state("transaction-1") == "EXECUTING"


def test_A21_actor_cannot_declare_verdict(run, tmp_path):
    ledger = begin(run, tmp_path)
    with pytest.raises(ClosureError):
        ledger.append(
            event(run, ledger, "INDETERMINATE", role="actor", packet=packet(run, ledger)), ledger.head
        )


def test_A21_idempotence_and_conflicting_id(run, tmp_path):
    ledger = begin(run, tmp_path)
    old_head = ledger.head
    e = event(run, ledger, "VERIFYING", receipt=run["receipts"][0])
    original = ledger.append(e, old_head)
    assert ledger.append(e, old_head) == original
    changed = copy.deepcopy(e["payload"]["body"])
    changed["refs"] = [digest(b"changed")]
    with pytest.raises(ClosureError):
        ledger.append(
            sign(run["keys"]["broker"], "ledger-event", changed, timestamp(run["start"])), ledger.head
        )


def test_A21_concurrent_append_has_one_winner(run, tmp_path):
    ledger = begin(run, tmp_path)
    old_head = ledger.head
    candidates = [
        event(run, ledger, "VERIFYING", receipt=run["receipts"][0], event_id=f"racer-{i}") for i in range(2)
    ]

    def append(e):
        try:
            ledger.append(e, old_head)
            return "accepted"
        except ClosureError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(append, candidates)) == ["accepted", "rejected"]
    ledger.verify()


@pytest.mark.parametrize("mutation", ["delete", "edit", "truncate"])
def test_A22_history_tamper_and_checkpoint(run, tmp_path, mutation):
    ledger = begin(run, tmp_path)
    checkpoint = ledger.checkpoint(run["keys"]["custodian"], timestamp(run["start"]))
    with sqlite3.connect(ledger.path) as db:
        if mutation == "delete":
            db.execute("DELETE FROM events WHERE sequence=2")
        elif mutation == "edit":
            db.execute("UPDATE events SET event_hash=? WHERE sequence=2", (digest(b"changed"),))
        else:
            db.execute("DELETE FROM events WHERE sequence>3")
    with pytest.raises(ClosureError):
        ledger.verify(checkpoint)


def test_A08_unknown_execution_recovery_requires_signed_packet(run, tmp_path):
    ledger = begin(run, tmp_path)
    result = packet(run, ledger, receipts=[])
    ledger.append(event(run, ledger, "INDETERMINATE", packet=result), ledger.head)
    ledger.append(event(run, ledger, "RECOVERY_REQUIRED"), ledger.head)
    assert ledger.state("transaction-1") == "RECOVERY_REQUIRED"


def test_A23_risk_event_preserves_technical_packet(run, tmp_path):
    ledger = begin(run, tmp_path)
    result = packet(run, ledger, receipts=[])
    original_hash = digest(result)
    ledger.append(event(run, ledger, "INDETERMINATE", packet=result), ledger.head)
    risk = sign(
        run["keys"]["owner"],
        "risk-acceptance",
        {
            "packet_hash": original_hash,
            "contract_hash": run["frozen"].hash,
            "rationale": "owner accepts documented risk",
            "expires_at": timestamp(run["start"] + 120_000),
        },
        timestamp(run["start"]),
    )
    ledger.append(event(run, ledger, "RISK_ACCEPTED", risk=risk), ledger.head)
    assert ledger.state("transaction-1") == "INDETERMINATE"
    assert digest(ledger.technical_packet("transaction-1")) == original_hash
    with pytest.raises(ClosureError):
        ledger.append(event(run, ledger, "ACCEPTED"), ledger.head)
