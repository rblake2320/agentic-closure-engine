import copy

import pytest
from test_verdicts import judge, replace

from closure_engine.crypto import TrustStore, sign
from closure_engine.protocol import ClosureError, canonical, digest, strict_loads, timestamp, validate


def test_receipt_id_conflict_is_indeterminate(run):
    altered = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    altered["recorded_at"] = timestamp(run["start"] + 1)
    extra = sign(run["keys"]["broker"], "action-receipt", altered, altered["recorded_at"])
    assert judge(run, receipts=run["receipts"] + [extra]).verdict == "INDETERMINATE"


def test_keys_cannot_be_reused_across_domains(run):
    trust = run["trust"].data
    trust["keys"][1]["public_key"] = trust["keys"][0]["public_key"]
    with pytest.raises(ClosureError):
        TrustStore.from_dict(trust)


def test_rfc8785_utf16_property_order_vector():
    keys = ["\ufb33", "\U0001f600", "\u20ac", "\u00f6", "\u0080", "1", "\r"]
    raw = canonical({k: k for k in keys})
    assert list(strict_loads(raw)) == ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]


def test_unknown_signature_algorithm_and_invalid_date(run):
    bad = copy.deepcopy(run["approval"])
    bad["algorithm"] = "none"
    with pytest.raises(ClosureError):
        validate("approval", bad)
    bad = copy.deepcopy(run["approval"])
    bad["payload"]["created_at"] = "2026-02-31T00:00:00Z"
    with pytest.raises(ClosureError):
        validate("approval", bad)


def test_oversize_input_does_not_enter_protocol():
    with pytest.raises(ClosureError):
        strict_loads('"' + "x" * 1_048_576 + '"')


def test_evidence_missing_and_ingestion_signature_failure(run):
    unknown_hash = digest(b"not retained")
    assert judge(run, records=replace(run, "primary", evidence_hash=unknown_hash)).verdict == "INDETERMINATE"
    records = copy.deepcopy(run["records"])
    records[0]["ingestion"]["signature"] = "00" * 64
    assert judge(run, records=records).verdict == "INDETERMINATE"
