# Observed validation

## Operating product 0.3.0 — 2026-10-11

The installed ACE wheel passed 276 tests and eleven legacy protocol-control CLI scenarios
with source imports disabled. Exact wheel SHA256:
`1f7e7218ab5f5270df5f7fb681e82aa9e3b7ce342fa91a521e1cc0cd6a11d863`.
All 44 packaged source/assets matched the repository byte for byte. Six additional real
Windows PowerShell 5.1/7 wrapper checks passed; their original assertions were retained.
Receipts: `evidence-runs/product-release-030-final/{receipt.json,source-manifest.json,checked-start.xml}`.
These installed checks include real HTTP targets, authenticated service processes, persistent
keys, custody, signature verification, input continuity, reconciliation and recovery. The
eleven legacy CLI controls use synthetic evidence and are not live deployment demonstrations.

Actual Docker/browser results are retained separately under `evidence-runs/product-deployment`:

| Receiving scenario | Observed result |
| --- | --- |
| Owner-approved catalog change through the shipped console | PROVEN, then ACCEPTED |
| Deployed value disagrees with the frozen desired value | DISPROVEN |
| Independently observed restoration | Child PROVEN; original RECOVERED, technical DISPROVEN retained |
| Wrong archive digest | Refused before installation files were written |
| Restore ownership failure | Incomplete state; startup refused |
| Same-archive restore retry and completed retry | Worked, then AlreadyRestored |
| Configuration export failure and same-source retry | Staging retained, then verified promotion |
| Restored deployment activation, custom backup and checked restart | Worked; canonical services restored afterward |
| Temporary viewer credential rotation/revocation, including restart | Old/revoked tokens 401; current token 200; owner action 403; existing enrollment preserved |

The last credential check used the shipped command in a network-free UID11007 container
mounted only to gateway auth and private test-token output. It did not perform the previously
denied Docker configuration inspection. Both test tokens were revoked and removed. A Docker
address-pool failure was diagnosed during restored activation; only this run's own inactive
containers/networks were reclaimed, and all identity/data volumes were preserved before the
successful retry. No global daemon settings or unrelated deployments were changed.

The following 0.2.0/0.1.0 sections are historical, tied to their original artifacts.

## Review hardening release 0.2.0

On 2026-10-11 the final installed Python3.13.5 wheel passed 100 tests and eleven independently
replayed/checkpointed CLI scenarios. Receipt: proofs/windows-python313-review/receipt.json.
Wheel SHA256: 4898526b956dcea5bf858c0175c9b2b7bdcdf6ca99254e79d4a5d9a5dfa782c1.
GitHub run38154775568 succeeded in all four Windows/Linux x Python3.12/3.13 jobs for source
ce3578923c699f9cef8164d48d94055f58024ce0. Retained-input replay, qualified mandatory-FAIL
precedence and inherited recovery-resource obligations are detailed in docs/review/HARDENING.md.
Its red regressions are retained locally. The independently versioned AWL adapter also tested
this exact installed wheel in a disposable HTTP application; AWL proofs/live-http retains
the actual read-backs, failures, verified restoration and portable public-key replay.

The 0.1.0 results below are historical and remain tied to their original policy/artifact.

Worked on 2026-10-11: the final installed Python 3.12.10 wheel passed 78 tests, zero failures, plus eleven CLI scenarios with independent replay and checkpoint verification. Imports resolved to the new environment's site-packages rather than src. The source was formatted and Ruff checks passed.

Final local retained receipt: `evidence-runs/release-journal-312/receipt.json`. A copy is committed at [proofs/windows-python312/receipt.json](../proofs/windows-python312/receipt.json).

Wheel: `agentic_closure_engine-0.1.0-py3-none-any.whl`.

SHA-256: `58cd1d10fed0f97b5ba53adc9a5caaf3c162740c1d41fec07786bcb0b8612f07`.

The receipt contains per-command durations/exit codes, installed origin, scenario outcomes, signed packet hashes and ledger heads. JUnit is retained beside it; public signed parent/recovery packets are retained in the installed suite's owned pytest temporary directory. The dependency inventory includes the build/verification environment, not only runtime dependencies.

## Scenario outcomes

| Scenario | Observed kernel verdict |
| --- | --- |
| Valid control | PROVEN |
| Mandatory invariant failure | DISPROVEN |
| Qualified evaluator-tamper finding | DISPROVEN |
| Previous artifact | INDETERMINATE |
| Missing deployment receipt | INDETERMINATE |
| Confirmed non-deployment with verified patch | PARTIALLY_PROVEN |
| Unreachable target observation | INDETERMINATE |
| Invalid observation signature | INDETERMINATE |
| Unknown interrupted action | INDETERMINATE, recovery required |
| Stale observations | INDETERMINATE |
| Exact replay retry | PROVEN without duplicate counting |

Deployment/behavior records are explicit fixtures. Crypto, baseline/candidate file reads, content-addressed evidence, SQLite history, concurrency and process interruption are real operations against owned local test data. No external model calls or mock cryptographic primitives were used.

## Failures caught and repaired

- Conflicting signed observations could previously retain a successful first sample. Their check now becomes unresolved; exact retries remain idempotent.
- A baseline existed in the contract but was not a required observation. Freeze now requires an independent baseline obligation and admission checks the retained artifact bytes.
- Different signed receipt bodies could reuse one ID with the same status. This now makes execution evidence unresolved.
- JSON Schema's optional date-time checker did not reject an impossible date in this environment. A strict UTC date parser is now registered explicitly.
- Reopened histories could be read without an independent checkpoint. Reopening now requires one, and checkpoint/trust bindings are checked on subsequent operations.
- Recovery could use an observation window preceding the parent's verdict. Recovery now checks approval/window ordering, baseline restoration and current-state preconditions.

Each repair has a named regression in the committed suite and retained red/green logs under evidence-runs. Real forced subprocess death during an uncommitted receipt left the durable EXECUTING state intact; restarted evaluation produced INDETERMINATE and RECOVERY_REQUIRED. A committed event with a lost reply was safely accepted once on retry.

The first CI run had one Windows/Python 3.13.15 WAL crash-reopen disk-I/O failure while the other three jobs passed. The next run passed all four, demonstrating an intermittent boundary rather than a proven repair. The new bounded single-writer store uses DELETE rollback journaling with FULL synchronization, closes connections even if initialization fails, and retains SQLite extended error names/codes. This contains the WAL/shared-memory path; the underlying dependency/OS cause is unclassified. Three independent killed-writer checks per environment and an explicit journal-mode regression guard the chosen storage behavior. Local Python 3.12.10 and 3.13.5 targeted controls passed; the final installed 3.12 suite passed all 78 checks.

## Scope

This is acceptance of the offline Phase 0 kernel. Real deployment, OS identity/resource/key access denial, a live durability window and actual target rollback are Phase 1 gates. The current CLI rejects non-fixture runtime modes. Laya is deliberately absent; no measured model benefit is claimed.

GitHub CI runs the installed-package verification on Windows/Linux with Python 3.12/3.13. Its observed status is tracked in Jira KAN-129; do not infer remote success from this local receipt.
