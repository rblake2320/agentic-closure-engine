# F06 Haiku helper: adversarial evidence-conflict tests

Owner: Haiku helper (claude-haiku-5-5), session 989022f1-bcb6-434d-9b00-6d7c59831f96
Branch: hardening/haiku-f06-20261011, baseline 7795b601eb18828f6b0906f734c7cea4b07de9a9
Owned files: tests/test_review_conflicts.py, docs/review/haiku-f06-results.md
No src, fixture, schema, workflow, or tracker edits.

## Baseline (run before new tests)

- Command: `.venv/Scripts/python.exe -m pytest -q` (private venv, package from this checkout)
- Result: 78 passed in 29.96s

## Registered expectations (fixed before execution)

| Test | Scenario | Expected verdict | Expected reason / state |
|---|---|---|---|
| test_F06_01 | Authorized verifier signs FAIL on one protected-a window sample, other samples PASS | DISPROVEN | MANDATORY_CHECK_FAILED |
| test_F06_02 | Signed FAIL with a nonce never issued by a challenge | PROVEN (FAIL rejected, not counted) | rejected CHALLENGE_MISMATCH |
| test_F06_03 | Signed FAIL on patch stage while primary PASS and deployment receipt EXECUTED | DISPROVEN | primary PASS, patch FAIL |
| test_F06_04 | Freshness boundary: evaluation at exactly max_age and deadline; one ms later | PROVEN at boundary; INDETERMINATE after | STALE_EVIDENCE past boundary |
| test_F06_05 | Clock-skew boundary: observation at now+skew admitted; now+skew+1 rejected | PROVEN at boundary; INDETERMINATE after | FUTURE_EVIDENCE |
| test_F06_06 | Deployment NOT_COMPLETED while receipt says EXECUTED | INDETERMINATE | CONFLICTING_EXECUTION_EVIDENCE |
| test_F06_07 | Deployment NOT_COMPLETED and a signed FAIL on patch | DISPROVEN | MANDATORY_CHECK_FAILED |
| test_F06_08 | NOT_COMPLETED on primary (allow_not_completed=false) | INDETERMINATE | INVALID_PARTIAL_RESULT rejected |
| test_F06_09 | Valid control: deployment NOT_COMPLETED, receipt NOT_DEPLOYED, patch PASS | PARTIALLY_PROVEN, recovery_required false | CONFIRMED_NON_COMPLETION |
| test_F06_10 | Valid control: all PASS with EXECUTED receipt, repeated evaluation | PROVEN every time | — |

## Limits of these tests (not claimed as coverage)

- Signature authentication proves who signed an observation, not that the observer was truthful. No test here claims otherwise; a validly signed false PASS is outside the kernel's detection.
- Only the single enrolled verifier identity exists in the fixture. Multi-verifier disagreement is not exercised.
- Receipt-state conflicts (two receipt ids, EXECUTED vs NOT_DEPLOYED) are not covered by this helper's tests.

## Execution

(filled after run, see below)

### Results (executed in this worktree)

- New tests: `.venv/Scripts/python.exe -m pytest tests/test_review_conflicts.py -v` → 10 passed (first run; no expectation changed)
- Full suite: `.venv/Scripts/python.exe -m pytest -q` → 88 passed (78 baseline + 10 new)
- Lint: `.venv/Scripts/ruff.exe check tests/test_review_conflicts.py` → All checks passed
- Machine transcript: `D:/projects/agentic-closure-engine/evidence-runs/review-20261011/haiku-f06-new-tests.txt` (outside the repo, runtime evidence not committed)

### Notes for root

- F06_02 keeps the existing design: an unchallenged signed FAIL is rejected (CHALLENGE_MISMATCH) and does not change the verdict. If the policy should be fail-closed for that case instead, that is a source decision for root; no source was changed here.
- No source repair was needed; no genuine failure occurred.
