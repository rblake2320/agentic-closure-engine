import copy

import pytest

from closure_engine.crypto import sign
from closure_engine.protocol import timestamp
from closure_engine.verdicts import evaluate


@pytest.mark.parametrize("offset,verdict", [(-1000, "PROVEN"), (-1001, "INDETERMINATE")])
def test_receipt_cannot_precede_binding_beyond_permitted_clock_skew(run, offset, verdict):
    body = copy.deepcopy(run["receipts"][0]["payload"]["body"])
    body["recorded_at"] = timestamp(run["start"] + offset)
    receipt = sign(run["keys"]["broker"], "action-receipt", body, body["recorded_at"])
    args = {k: run[k] for k in ("frozen", "binding", "records", "store", "trust")}
    result = evaluate(**args, receipts=[receipt], now=run["start"] + 60000)
    assert result.verdict == verdict
    if offset == -1001:
        assert any(item["reason"] == "PRE_BINDING_EVIDENCE" for item in result.rejected)
