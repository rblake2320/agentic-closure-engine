"""Owner live-browser regressions against real HTTP, custody, target and keys."""

import base64
import http.client
import json

import pytest
from test_runtime_api import RELEASE, call
from test_runtime_api import api as api  # noqa: F401
from test_runtime_e2e import WINDOW, artifact, run_to_verdict
from test_runtime_e2e import world as world  # noqa: F401

from closure_engine.protocol import ClosureError
from closure_engine.runtime import Runtime


def proposal(tx, raw=None):
    return {
        "target_id": "shop/api",
        "transaction_id": tx,
        "artifact_base64": base64.b64encode(artifact(2) if raw is None else raw).decode(),
        "expect": {"primary": 2},
        "intent": "Live review regression",
        **WINDOW,
    }


@pytest.mark.parametrize(
    "tx",
    [
        "adv/../../evil",
        "existing/recovery",
        "../evil",
        "..",
        "a..b",
        "x\\evil",
        "a%2fb",
        "a\x00b",
        "a" * 129,
        "",
    ],
)
def test_external_ids_refused_without_persistence(api, tx):
    before = call(api, "GET", "/api/v1/status", token=RELEASE)[1]
    status, value = call(api, "POST", "/api/v1/transactions", proposal(tx), RELEASE)
    assert (status, value.get("error")) == (400, "INVALID_TRANSACTION_ID")
    assert call(api, "GET", "/api/v1/status", token=RELEASE)[1] == before


@pytest.mark.parametrize("size", [524289, 600000, 700000])
def test_decoded_artifact_limit_is_512_kib(api, size):
    status, value = call(api, "POST", "/api/v1/transactions", proposal("large", b"x" * size), RELEASE)
    assert (status, value.get("error")) == (413, "ARTIFACT_TOO_LARGE")


def test_raw_http_size_limit_is_clean_json_413(api):
    connection = http.client.HTTPConnection("127.0.0.1", api, timeout=15)
    # Send headers only: server must reject from declared length, before requiring body bytes.
    connection.putrequest("POST", "/api/v1/transactions")
    connection.putheader("Authorization", "Bearer " + RELEASE)
    connection.putheader("Content-Type", "application/json")
    connection.putheader("Content-Length", "2097153")
    connection.endheaders()
    response = connection.getresponse()
    data = json.loads(response.read())
    connection.close()
    assert (response.status, data.get("error")) == (413, "INPUT_TOO_LARGE")


def test_unsupported_transaction_subroute_is_route_not_found(api):
    assert call(api, "POST", "/api/v1/transactions", proposal("route-test"), RELEASE)[0] == 201
    status, value = call(api, "GET", "/api/v1/transactions/route-test/ledger", token=RELEASE)
    assert (status, value.get("error")) == (404, "ROUTE_NOT_FOUND")


def test_terminal_observation_and_recovery_completion_refuse_without_mutation(world):
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    _, result = run_to_verdict(runtime, "terminal-test", artifact(2))
    assert result["verdict"] == "PROVEN"
    runtime.accept("terminal-test")
    before = runtime.status("terminal-test")
    for action in (runtime.observe, runtime.complete_recovery):
        with pytest.raises(ClosureError, match="TRANSACTION_TERMINAL"):
            action("terminal-test")
        assert runtime.status("terminal-test") == before


def test_refused_deployment_explains_format_and_disables_recovery(world):
    deployment, pin, _ = world
    runtime = Runtime(deployment, pin)
    runtime.propose(
        "shop/api", "invalid-format", b'{"answer":2}', intent="bad format", expect={"primary": 2}, **WINDOW
    )
    for action in (runtime.approve, runtime.freeze, runtime.baseline):
        action("invalid-format")
    result = runtime.run("invalid-format")
    assert result["verdict"] == "DISPROVEN"
    assert result["deployment"]["reason_code"] == "ARTIFACT_FORMAT_INVALID"
    assert result["deployment"]["target_http_status"] == 400
    receipt = runtime.custody.receipts("invalid-format")[0]["payload"]["body"]
    assert receipt["reason_code"] == "ARTIFACT_FORMAT_INVALID"
    view = runtime.status("invalid-format")
    assert view["recovery"]["eligible"] is False
    assert "recover" not in view["allowed_actions"]
    assert view["deployment"]["reason_code"] == "ARTIFACT_FORMAT_INVALID"


def test_artifact_exact_boundary_is_accepted_and_round_trips(api):
    raw = b"x" * 524288
    status, result = call(api, "POST", "/api/v1/transactions", proposal("boundary", raw), RELEASE)
    assert status == 201, result
    status, stored = call(api, "GET", "/api/v1/transactions/boundary", token=RELEASE)
    assert status == 200
    from closure_engine.protocol import digest

    assert stored["artifact_hash"] == digest(raw)


def test_terminal_actions_are_http_409(api):
    assert call(api, "POST", "/api/v1/transactions", proposal("finished"), RELEASE)[0] == 201
    for action in ("approve", "freeze", "baseline", "run", "accept"):
        status, result = call(api, "POST", "/api/v1/transactions/finished/" + action, {}, RELEASE)
        assert status == 200, result
    before = call(api, "GET", "/api/v1/status", token=RELEASE)[1]
    for action in ("observe", "recover-complete"):
        status, result = call(api, "POST", "/api/v1/transactions/finished/" + action, {}, RELEASE)
        assert (status, result["error"]) == (409, "TRANSACTION_TERMINAL")
    assert call(api, "GET", "/api/v1/status", token=RELEASE)[1] == before


def test_unsupported_method_returns_json_405_allow(api):
    connection = http.client.HTTPConnection("127.0.0.1", api, timeout=15)
    connection.request("DELETE", "/api/v1/transactions", headers={"Authorization": "Bearer " + RELEASE})
    response = connection.getresponse()
    assert response.status == 405
    assert response.getheader("Allow") == "GET, POST"
    assert json.loads(response.read())["error"] == "METHOD_NOT_ALLOWED"
    connection.close()
