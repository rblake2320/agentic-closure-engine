"""Replay reuse requires unchanged physical custody; these controls use real files/keys."""

import copy
import cProfile
import os
import pstats

import pytest

from closure_engine.crypto import TrustStore, sign
from closure_engine.protocol import GENESIS, ClosureError, digest
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
