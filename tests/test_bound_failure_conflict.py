import copy

from test_review_conflicts import multi_judge, multi_run

from closure_engine.crypto import sign
from closure_engine.protocol import digest


def test_bound_mandatory_failure_wins_even_when_digest_sorts_after_pass(run, tmp_path):
    m = multi_run(run, tmp_path)
    fail = m["observe"](m["keys"]["verifier2"], "primary", "FAIL")
    passed = m["observe"](m["keys"]["verifier"], "primary", "PASS")
    body = copy.deepcopy(passed["observation"]["payload"]["body"])
    fail_body = copy.deepcopy(fail["observation"]["payload"]["body"])
    for index in range(100):
        body["observation_id"] = "primary-pass-" + str(index)
        obs = sign(m["keys"]["verifier"], "observation", body, body["observed_at"])
        ing = sign(
            m["keys"]["custodian"],
            "ingestion",
            {"envelope_hash": digest(obs), "received_at": body["observed_at"]},
            body["observed_at"],
        )
        pair = {"observation": obs, "ingestion": ing}
        fail_body["observation_id"] = "primary-fail-" + str(index)
        fail_obs = sign(m["keys"]["verifier2"], "observation", fail_body, fail_body["observed_at"])
        fail_ing = sign(
            m["keys"]["custodian"],
            "ingestion",
            {"envelope_hash": digest(fail_obs), "received_at": fail_body["observed_at"]},
            fail_body["observed_at"],
        )
        fail = {"observation": fail_obs, "ingestion": fail_ing}
        if digest(pair) < digest(fail):
            result = multi_judge(m, records=[pair, fail])
            assert result.verdict == "DISPROVEN"
            assert result.checks["primary"] == "FAIL"
            return
    raise AssertionError("Could not construct PASS-first digest order")
