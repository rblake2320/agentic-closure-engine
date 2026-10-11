"""Bulk replay retains the normal admission rules and never commits a rejected history."""

import copy

import pytest
from test_ledger import begin, event, packet

from closure_engine.crypto import sign
from closure_engine.ledger import Ledger
from closure_engine.protocol import GENESIS, ClosureError, timestamp


@pytest.fixture
def history(run, tmp_path):
    source = begin(run, tmp_path / "source")
    source.append(event(run, source, "VERIFYING", receipt=run["receipts"][0]), source.head)
    source.append(event(run, source, "OBSERVING", packet=packet(run, source, now=run["start"])), source.head)
    source.append(event(run, source, "PROVEN", packet=packet(run, source)), source.head)
    source.append(event(run, source, "ACCEPTED"), source.head)
    exported = source.audit_export()
    checkpoint = source.checkpoint(run["keys"]["custodian"], timestamp(run["start"] + 60_000))
    target = Ledger(tmp_path / "target.sqlite", run["trust"], run["store"])
    return source, target, exported["events"], checkpoint


def test_bulk_public_replay_matches_normal_accepted_history(run, history):
    source, target, events, checkpoint = history
    result = target.import_history([run["frozen"]], events, checkpoint)
    assert result["verified_head"] == source.head
    assert result["sequence"] == 9
    assert result["transactions"] == {"transaction-1": "ACCEPTED"}
    assert result["packets"]["transaction-1"] == source.technical_packet("transaction-1")


def test_bulk_invalid_signature_rolls_back_every_imported_row(run, history):
    _, target, events, checkpoint = history
    changed = copy.deepcopy(events)
    changed[-1]["payload"]["body"]["previous_hash"] = GENESIS
    with pytest.raises(ClosureError, match="SIGNATURE_INVALID"):
        target.import_history([run["frozen"]], changed, checkpoint)
    assert target.summary() == {"verified_head": GENESIS, "sequence": 0, "transactions": {}}
    with target._db() as db:
        assert db.execute("SELECT COUNT(*) FROM contracts").fetchone()[0] == 0


def test_bulk_truncated_history_refuses_external_checkpoint(run, history):
    _, target, events, checkpoint = history
    with pytest.raises(ClosureError, match="CHECKPOINT_MISMATCH_OR_TRUNCATION"):
        target.import_history([run["frozen"]], events[:-1], checkpoint)
    assert target.sequence == 0


def test_bulk_requires_exact_final_checkpoint_not_just_a_valid_prefix(run, history):
    _, target, events, _ = history
    genesis = sign(
        run["keys"]["custodian"],
        "checkpoint",
        {
            "sequence": 0,
            "head_hash": GENESIS,
            "trust_hash": run["trust"].hash,
        },
        timestamp(run["start"]),
    )
    with pytest.raises(ClosureError, match="CHECKPOINT_DOES_NOT_MATCH_EXPORT"):
        target.import_history([run["frozen"]], events, genesis)
    assert target.sequence == 0


def test_bulk_prior_fork_anchor_refused_before_commit(run, history):
    _, target, events, checkpoint = history
    prior = sign(
        run["keys"]["custodian"],
        "checkpoint",
        {
            "sequence": 1,
            "head_hash": GENESIS,
            "trust_hash": run["trust"].hash,
        },
        timestamp(run["start"]),
    )
    with pytest.raises(ClosureError, match="CHECKPOINT_MISMATCH_OR_TRUNCATION"):
        target.import_history([run["frozen"]], events, checkpoint, prior_checkpoint=prior)
    assert target.sequence == 0


def test_bulk_never_replaces_an_existing_verified_history(run, history):
    _, target, events, checkpoint = history
    target.import_history([run["frozen"]], events, checkpoint)
    with pytest.raises(ClosureError, match="IMPORT_TARGET_NOT_EMPTY"):
        target.import_history([run["frozen"]], events, checkpoint)
    assert target.sequence == 9


ROLE_OF_STATE = {
    "DRAFT": "actor",
    "APPROVED": "owner",
    "BASELINED": "verifier",
    "EXECUTING": "broker",
    "VERIFYING": "broker",
    "ACCEPTED": "owner",
}


def _resign_chain(run, events, start_index):
    """Re-sign events from ``start_index`` with consistent sequence and previous-hash links,
    as an insider holding every role key could. Signatures are valid; history is not."""
    from closure_engine.protocol import digest

    out = copy.deepcopy(events[:start_index])
    for envelope in events[start_index:]:
        body = copy.deepcopy(envelope["payload"]["body"])
        body["sequence"] = len(out) + 1
        body["previous_hash"] = digest(out[-1]) if out else GENESIS
        role = ROLE_OF_STATE.get(body["state"], "authority")
        out.append(sign(run["keys"][role], "ledger-event", body, envelope["payload"]["created_at"]))
    return out


def _nothing_committed(target):
    assert target.summary() == {"verified_head": GENESIS, "sequence": 0, "transactions": {}}
    with target._db() as db:
        assert db.execute("SELECT COUNT(*) FROM contracts").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_bulk_list_order_does_not_change_the_committed_history(run, history):
    source, target, events, checkpoint = history
    shuffled = [events[i] for i in (0, 1, 2, 3, 4, 6, 5, 7, 8)]  # transport order only
    result = target.import_history([run["frozen"]], shuffled, checkpoint)
    assert result["verified_head"] == source.head and result["sequence"] == 9


def test_bulk_resigned_reordered_history_is_refused_and_rolled_back(run, history):
    _, target, events, checkpoint = history
    swapped = events[:5] + [events[6], events[5]] + events[7:]  # OBSERVING before VERIFYING
    forged = _resign_chain(run, swapped, 5)
    with pytest.raises(ClosureError, match="ILLEGAL_TRANSITION"):
        target.import_history([run["frozen"]], forged, checkpoint)
    _nothing_committed(target)


def test_bulk_duplicate_event_is_refused_and_rolled_back(run, history):
    _, target, events, checkpoint = history
    with pytest.raises(ClosureError, match="LEDGER_STORAGE_ERROR"):
        target.import_history([run["frozen"]], events + [events[-1]], checkpoint)
    _nothing_committed(target)


def test_bulk_duplicate_event_id_with_new_sequence_is_refused_and_rolled_back(run, history):
    _, target, events, checkpoint = history
    from closure_engine.protocol import digest

    body = copy.deepcopy(events[-1]["payload"]["body"])
    body.update(sequence=10, previous_hash=digest(events[-1]))  # same event_id, appended
    duplicate = sign(run["keys"]["owner"], "ledger-event", body, events[-1]["payload"]["created_at"])
    with pytest.raises(ClosureError, match="LEDGER_STORAGE_ERROR"):
        target.import_history([run["frozen"]], events + [duplicate], checkpoint)
    _nothing_committed(target)
