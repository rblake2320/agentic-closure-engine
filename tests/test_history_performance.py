"""Replay reuse requires unchanged physical custody; these controls use real files/keys."""

import copy
import cProfile
import json
import os
import pstats
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_ledger import begin, event
from test_ledger import packet as ledger_packet

from closure_engine.crypto import TrustStore, sign
from closure_engine.ledger import Ledger
from closure_engine.protocol import GENESIS, ClosureError, canonical, digest, timestamp
from closure_engine.store import EvidenceStore
from closure_engine.verdicts import close_run, replay_packet


def packet_of(run, **changes):
    args = {key: run[key] for key in ("frozen", "binding", "records", "receipts", "store", "trust")}
    args.update(authority=run["keys"]["authority"], ledger_head=GENESIS, now=run["start"] + 60000)
    args.update(changes)
    return close_run(**args)


def evaluator_in_custody(run):
    assert run["store"].put(b"operator-installed-evaluator-v1") == run["frozen"].data["evaluator_hash"]


def eval_count(profile):
    return sum(stats[0] for key, stats in pstats.Stats(profile).stats.items() if key[2] == "evaluate")


def test_identical_packet_reuses_only_previous_full_reconstruction(run):
    evaluator_in_custody(run)
    packet = packet_of(run)
    profiler = cProfile.Profile()
    profiler.enable()
    first = replay_packet(packet, run["store"], run["trust"])
    second = replay_packet(copy.deepcopy(packet), run["store"], run["trust"])
    profiler.disable()
    assert first == second and first["verdict"] == "PROVEN"
    assert eval_count(profiler) == 1
    assert run["store"].replay_cache_info()["entries"] == 1


@pytest.mark.parametrize("subject", ("evidence", "inputs", "evaluator"))
@pytest.mark.parametrize("mutation", ("delete", "edit", "same-size-and-mtime"))
def test_cache_hit_reopens_every_custody_dependency_and_refuses_change(run, subject, mutation):
    evaluator_in_custody(run)
    packet = packet_of(run)
    body = replay_packet(packet, run["store"], run["trust"])
    reference = {
        "evidence": run["records"][0]["observation"]["payload"]["body"]["evidence_hash"],
        "inputs": body["inputs_hash"],
        "evaluator": body["evaluator_hash"],
    }[subject]
    path = run["store"].path_for(reference)
    saved, before = path.read_bytes(), path.stat()
    if mutation == "delete":
        path.unlink()
    else:
        path.write_bytes(bytes([saved[0] ^ 1]) + saved[1:])
        if mutation == "same-size-and-mtime":
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert path.stat().st_size == before.st_size and path.stat().st_mtime_ns == before.st_mtime_ns
    for _ in range(2):
        with pytest.raises(ClosureError, match="EVIDENCE_MISSING|EVIDENCE_HASH_MISMATCH"):
            replay_packet(packet, run["store"], run["trust"])
    path.write_bytes(saved)
    assert replay_packet(packet, run["store"], run["trust"]) == body


def test_returned_mutable_results_do_not_poison_later_replay(run):
    evaluator_in_custody(run)
    packet = packet_of(run)
    original = replay_packet(packet, run["store"], run["trust"])
    returned = replay_packet(packet, run["store"], run["trust"])
    returned["checks"]["primary"] = "FAIL"
    returned["reason_codes"].append("SCHEMA_INVALID")
    assert replay_packet(packet, run["store"], run["trust"]) == original


def test_changed_packet_signature_and_enrollment_are_not_cached_authority(run):
    evaluator_in_custody(run)
    packet = packet_of(run)
    replay_packet(packet, run["store"], run["trust"])
    altered = copy.deepcopy(packet)
    altered["signature"] = "00" * 64
    with pytest.raises(ClosureError, match="SIGNATURE_INVALID"):
        replay_packet(altered, run["store"], run["trust"])
    enrollment = copy.deepcopy(run["trust"].data)
    next(item for item in enrollment["keys"] if item["role"] == "authority")["role"] = "actor"
    changed = TrustStore.from_dict(enrollment)
    with pytest.raises(ClosureError, match="SIGNING_PURPOSE_DENIED"):
        replay_packet(packet, run["store"], changed)


def test_validly_signed_fabricated_proven_is_still_reconstructed_and_refused(run):
    evaluator_in_custody(run)
    valid = packet_of(run)
    replay_packet(valid, run["store"], run["trust"])
    failing_records = [
        record
        for record in run["records"]
        if record["observation"]["payload"]["body"]["check_id"] != "primary"
    ]
    failing_records.append(run["observation"]("primary", "FAIL"))
    actual = packet_of(run, records=failing_records)
    assert replay_packet(actual, run["store"], run["trust"])["verdict"] == "DISPROVEN"
    fabricated = copy.deepcopy(actual["payload"]["body"])
    fabricated.update(verdict="PROVEN", reason_codes=[], recovery_required=False)
    fabricated["checks"]["primary"] = "PASS"
    forged = sign(run["keys"]["authority"], "closure-packet", fabricated, fabricated["evaluated_at"])
    with pytest.raises(ClosureError, match="PACKET_REPLAY_MISMATCH"):
        replay_packet(forged, run["store"], run["trust"])


def test_failed_custody_read_never_memoizes_an_absence_result(run):
    evaluator_in_custody(run)
    missing = b"evidence that will appear only after the initial replay"
    records = [
        record
        for record in run["records"]
        if record["observation"]["payload"]["body"]["check_id"] != "primary"
    ]
    record = run["observation"]("primary")
    observation = copy.deepcopy(record["observation"]["payload"]["body"])
    observation["evidence_hash"] = digest(missing)
    signed = sign(
        run["keys"]["verifier"], "observation", observation, record["observation"]["payload"]["created_at"]
    )
    ingestion = copy.deepcopy(record["ingestion"]["payload"]["body"])
    ingestion["envelope_hash"] = digest(signed)
    records.append(
        {
            "observation": signed,
            "ingestion": sign(
                run["keys"]["custodian"], "ingestion", ingestion, record["ingestion"]["payload"]["created_at"]
            ),
        }
    )
    packet = packet_of(run, records=records)
    assert replay_packet(packet, run["store"], run["trust"])["verdict"] == "INDETERMINATE"
    assert run["store"].replay_cache_info()["entries"] == 0
    run["store"].put(missing)
    with pytest.raises(ClosureError, match="PACKET_REPLAY_MISMATCH"):
        replay_packet(packet, run["store"], run["trust"])


def test_legacy_external_evaluator_semantics_remain_uncached(run):
    packet = packet_of(run)
    profiler = cProfile.Profile()
    profiler.enable()
    assert replay_packet(packet, run["store"], run["trust"])["verdict"] == "PROVEN"
    assert replay_packet(packet, run["store"], run["trust"])["verdict"] == "PROVEN"
    profiler.disable()
    assert eval_count(profiler) == 2
    assert run["store"].replay_cache_info()["entries"] == 0


def test_cache_count_budget_and_root_ownership_are_bounded(run, tmp_path):
    store = EvidenceStore(tmp_path / "bounded", replay_cache_entries=2, replay_cache_bytes=16384)
    reference = store.put(b"actual-custody")
    for index in range(8):
        store.remember_replay((str(index),), [reference], {"value": index})
        assert store.replay_cache_info()["entries"] <= 2
        assert store.replay_cache_info()["bytes"] <= 16384
    assert store.cached_replay(("0",)) is None
    assert store.cached_replay(("7",)) == {"value": 7}
    other = EvidenceStore(tmp_path / "other")
    assert other.cached_replay(("7",)) is None
    limited = EvidenceStore(tmp_path / "limited", replay_cache_entries=10, replay_cache_bytes=1)
    limited.remember_replay(("entry",), [], {"large": "x" * 1000})
    assert limited.replay_cache_info() == {"entries": 0, "bytes": 0}


def test_reopen_has_no_memoized_success_and_missing_raw_inputs_still_refuse(run):
    evaluator_in_custody(run)
    packet = packet_of(run)
    body = replay_packet(packet, run["store"], run["trust"])
    run["store"].path_for(body["inputs_hash"]).unlink()
    reopened = EvidenceStore(run["store"].root, create=False)
    assert reopened.replay_cache_info()["entries"] == 0
    with pytest.raises(ClosureError, match="EVIDENCE_MISSING"):
        replay_packet(packet, reopened, run["trust"])


def accepted_ledger(run, tmp_path):
    evaluator_in_custody(run)
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    initial = ledger_packet(run, ledger, now=run["start"])
    ledger.append(event(run, ledger, "OBSERVING", packet=initial), ledger.head)
    closed = ledger_packet(run, ledger)
    ledger.append(event(run, ledger, "PROVEN", packet=closed), ledger.head)
    ledger.append(event(run, ledger, "ACCEPTED"), ledger.head)
    ledger.snapshot()  # prime all three successful validation pools
    return ledger


@pytest.mark.parametrize("mutation", ("delete", "timestamp-with-recomputed-hash", "duplicate-id", "order"))
def test_authenticated_old_bytes_do_not_authorize_changed_physical_history(run, tmp_path, mutation):
    ledger = accepted_ledger(run, tmp_path)
    checkpoint = ledger.checkpoint(run["keys"]["custodian"], timestamp(run["start"] + 60000))
    ledger.anchor = checkpoint
    before = ledger.path.stat()
    with sqlite3.connect(ledger.path) as db:
        if mutation == "delete":
            db.execute("DELETE FROM events WHERE sequence=(SELECT MAX(sequence) FROM events)")
        elif mutation == "timestamp-with-recomputed-hash":
            row = db.execute("SELECT envelope FROM events WHERE sequence=1").fetchone()
            from closure_engine.protocol import strict_loads

            altered = strict_loads(row[0])
            altered["payload"]["created_at"] = timestamp(run["start"] + 123)
            db.execute(
                "UPDATE events SET envelope=?,event_hash=? WHERE sequence=1",
                (canonical(altered), digest(altered)),
            )
        elif mutation == "duplicate-id":
            db.execute("UPDATE events SET event_id='fake-literal-id' WHERE sequence=1")
        else:
            db.execute("UPDATE events SET sequence=900 WHERE sequence=1")
    os.utime(ledger.path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ClosureError):
        ledger.snapshot()  # warm prefix must invalidate, then classify with native replay
    with pytest.raises(ClosureError):
        ledger.verify(checkpoint)
    from closure_engine.ledger import Ledger

    with pytest.raises(ClosureError):
        Ledger(
            ledger.path, run["trust"], EvidenceStore(run["store"].root, create=False), checkpoint=checkpoint
        )


@pytest.mark.parametrize("column", ("contract", "approval"))
def test_contract_authentication_is_bound_to_actual_reloaded_bytes(run, tmp_path, column):
    ledger = accepted_ledger(run, tmp_path)
    with sqlite3.connect(ledger.path) as db:
        row = db.execute(f"SELECT {column} FROM contracts LIMIT 1").fetchone()
        from closure_engine.protocol import strict_loads

        altered = strict_loads(row[0])
        if column == "contract":
            altered["intent"] = "Unauthorized changed intent"
        else:
            altered["signature"] = "00" * 64
        db.execute(f"UPDATE contracts SET {column}=?", (canonical(altered),))
    with pytest.raises(ClosureError):
        ledger.snapshot()


def test_prefix_reuses_validated_state_but_explicit_audit_applies_all_transitions(run, tmp_path):
    ledger = accepted_ledger(run, tmp_path)
    profile = cProfile.Profile()
    profile.enable()
    first, second = ledger.snapshot(), ledger.snapshot()
    profile.disable()
    assert first == second
    stats = pstats.Stats(profile).stats
    applied = sum(data[0] for key, data in stats.items() if key[2] == "_apply")
    assert applied == 0
    audit = cProfile.Profile()
    audit.enable()
    ledger.verify()
    audit.disable()
    assert (
        sum(data[0] for key, data in pstats.Stats(audit).stats.items() if key[2] == "_apply")
        == first["sequence"]
    )
    assert ledger.snapshot() == first
    info = run["store"].verification_cache_info()
    assert info["pools"]["auth/event"] and info["pools"]["auth/contract"] and info["pools"]["replay"]
    assert info["entries"] <= 8192 and info["bytes"] <= 64 * 1024 * 1024


def test_all_authentication_and_replay_pools_share_one_budget(tmp_path):
    store = EvidenceStore(tmp_path / "one-budget", replay_cache_entries=3, replay_cache_bytes=4096)
    for index in range(20):
        store.remember_authentication("event", (str(index),), (b"event" + bytes([index]),))
        store.remember_authentication("contract", (str(index),), (b"contract", b"approval"))
        store.remember_replay((str(index),), [], {"verdict": "PROVEN", "index": index})
        store._remember_prefix((str(index),), [], {"states": {}, "rows": []})
        info = store.verification_cache_info()
        assert info["entries"] <= 3 and info["bytes"] <= 4096
    assert store._cached_prefix(("19",)) == ((), {"states": {}, "rows": []})
    assert not store.authentication_cached("event", ("19",), (b"eventCHANGED",))


@pytest.mark.parametrize("subject", ("baseline", "evaluator", "inputs", "raw"))
@pytest.mark.parametrize("mutation", ("delete", "same-size-and-mtime"))
def test_prefix_hit_physically_rechecks_transitive_custody(run, tmp_path, subject, mutation):
    ledger = accepted_ledger(run, tmp_path)
    assert run["store"].verification_cache_info()["pools"]["prefix"]
    body = ledger.technical_packet("transaction-1")["payload"]["body"]
    reference = {
        "baseline": run["baseline"],
        "evaluator": body["evaluator_hash"],
        "inputs": body["inputs_hash"],
        "raw": run["records"][0]["observation"]["payload"]["body"]["evidence_hash"],
    }[subject]
    path = run["store"].path_for(reference)
    raw, stat = path.read_bytes(), path.stat()
    if mutation == "delete":
        path.unlink()
    else:
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    with pytest.raises(ClosureError):
        ledger.snapshot()
    path.write_bytes(raw)
    assert ledger.state("transaction-1") == "ACCEPTED"


def test_cached_suffix_preserves_prior_qualified_fail_and_accepts_truthful_control(run, tmp_path):
    from test_independent_boundary_review import _fail_sample

    evaluator_in_custody(run)
    ledger = begin(run, tmp_path)
    ledger.append(event(run, ledger, "VERIFYING", receipt=run["receipts"][0]), ledger.head)
    records = run["records"] + [_fail_sample(run)]
    immediate = ledger_packet(run, ledger, now=run["start"], records=records)
    ledger.append(event(run, ledger, "OBSERVING", packet=immediate), ledger.head)
    assert ledger.snapshot()["transactions"]["transaction-1"] == "OBSERVING"
    assert run["store"].verification_cache_info()["pools"]["prefix"]
    omitted = ledger_packet(run, ledger, records=run["records"])
    assert omitted["payload"]["body"]["verdict"] == "PROVEN"
    with pytest.raises(ClosureError, match="LEDGERED_EVIDENCE_OMITTED"):
        ledger.append(event(run, ledger, "PROVEN", packet=omitted), ledger.head)
    truthful = ledger_packet(run, ledger, records=records)
    fabricated = copy.deepcopy(truthful["payload"]["body"])
    fabricated.update(verdict="PROVEN", recovery_required=False, reason_codes=[])
    fabricated["checks"]["protected-a"] = "PASS"
    false_packet = sign(run["keys"]["authority"], "closure-packet", fabricated, fabricated["evaluated_at"])
    with pytest.raises(ClosureError, match="PACKET_REPLAY_MISMATCH"):
        ledger.append(event(run, ledger, "PROVEN", packet=false_packet), ledger.head)
    ledger.append(event(run, ledger, "DISPROVEN", packet=truthful), ledger.head)
    warm = ledger.snapshot()
    checkpoint = ledger.checkpoint(run["keys"]["custodian"], timestamp(run["start"] + 60000))
    reopened = Ledger(ledger.path, run["trust"], EvidenceStore(run["store"].root), checkpoint)
    assert reopened.snapshot() == warm


def test_prefix_result_mutation_and_trust_swap_cannot_change_authority(run, tmp_path):
    ledger = accepted_ledger(run, tmp_path)
    before = ledger.snapshot()
    changed = ledger.snapshot()
    changed["transactions"]["transaction-1"] = "DISPROVEN"
    changed["packets"]["transaction-1"]["signature"] = "00" * 64
    assert ledger.snapshot() == before
    enrolled = copy.deepcopy(run["trust"].data)
    enrolled["keys"][0]["issuer"] += "-changed"
    ledger.trust = TrustStore.from_dict(enrolled)
    with pytest.raises(ClosureError, match="LEDGER_TRUST_MISMATCH"):
        ledger.snapshot()


def test_real_process_kill_after_validated_prefix_before_append_cold_replays(run, tmp_path):
    evaluator_in_custody(run)
    ledger = begin(run, tmp_path)
    checkpoint = ledger.checkpoint(run["keys"]["custodian"], timestamp(run["start"]))
    request = event(run, ledger, "VERIFYING", receipt=run["receipts"][0])
    public = tmp_path / "public.json"
    public.write_bytes(canonical({"trust": run["trust"].data, "checkpoint": checkpoint}))
    script = tmp_path / "guarded.py"
    script.write_text(
        "import sys,time,json\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n"
        "from closure_engine.ledger import Ledger\nfrom closure_engine.crypto import TrustStore\n"
        "from closure_engine.store import EvidenceStore\nfrom closure_engine.protocol import strict_loads\n"
        "root=Path(sys.argv[2]); p=strict_loads((root/'public.json').read_bytes())\n"
        "s=EvidenceStore(sys.argv[3],create=False)\n"
        "l=Ledger(root/'ledger.sqlite',TrustStore.from_dict(p['trust']),s,p['checkpoint'])\n"
        "result=l.snapshot(); assert s.verification_cache_info()['pools']['prefix']\n"
        "(root/'ready').write_text(json.dumps(result))\n"
        "while not (root/'release').exists(): time.sleep(.05)\n",
        encoding="utf-8",
    )
    import closure_engine

    child = subprocess.Popen(
        [
            sys.executable,
            "-I",
            str(script),
            str(Path(closure_engine.__file__).parent.parent),
            str(tmp_path),
            str(run["store"].root),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 15
        while not (tmp_path / "ready").exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.025)
        assert (tmp_path / "ready").exists(), child.communicate(timeout=1)
        assert json.loads((tmp_path / "ready").read_text()) == ledger.snapshot()
        child.kill()  # exact Popen-owned PID only; never an inventory-derived process
        child.communicate(timeout=5)
        assert child.returncode != 0
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
    profile = cProfile.Profile()
    profile.enable()
    cold = Ledger(ledger.path, run["trust"], EvidenceStore(run["store"].root), checkpoint)
    profile.disable()
    assert sum(data[0] for key, data in pstats.Stats(profile).stats.items() if key[2] == "_apply") == 5
    assert cold.state("transaction-1") == "EXECUTING"
    cold.append(request, cold.head)
    assert cold.state("transaction-1") == "VERIFYING"
    assert not list(tmp_path.rglob("*prefix*.json"))
