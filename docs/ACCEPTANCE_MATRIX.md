# Planned acceptance and adversarial matrix

Status: every executable test below is PLANNED / NOT RUN. The current repository is a design package, not a tested kernel.

Use one bounded contract with a primary check and at least two mandatory invariants. Capture expected outcomes before implementation. Every negative case has an equivalent valid control. A suite that rejects all inputs fails acceptance.

| ID | Concrete scenario | Expected result |
| --- | --- | --- |
| A01 | Correct artifact deployed; primary and two invariants pass; complete fresh window | PROVEN, then separately authorized ACCEPTED |
| A02 | Independently authenticated protected evaluator modification | DISPROVEN or broker execution denied; no accepted deployment |
| A03 | Observation signed correctly but references previous artifact | Reject ARTIFACT_MISMATCH; INDETERMINATE when required proof is missing |
| A04 | Primary passes, mandatory protected invariant fails | DISPROVEN regardless of other successful checks |
| A05 | Patch stage verified and authenticated NOT_DEPLOYED receipt; applicable invariants pass | PARTIALLY_PROVEN |
| A06 | Patch verified but deployment receipt/observation absent | INDETERMINATE, never partial by inference |
| A07 | Verifier cannot reach the declared target | UNKNOWN observation; INDETERMINATE |
| A08 | Crash after durable action intent with no reliable result | INDETERMINATE plus RECOVERY_REQUIRED; reconcile before any retry |
| A09 | Approved rollback performed and independently restores scoped baseline | Child PROVEN, parent RECOVERED; original verdict unchanged |
| A10 | Broker reports rollback success but baseline restoration fails | Child DISPROVEN, parent RECOVERY_FAILED |
| A11 | All valid controls rejected | Acceptance-suite failure, regardless of negative-case results |
| A12 | Correct observation beyond max age or after expiry | Reject STALE_EVIDENCE; required unknown yields INDETERMINATE |
| A13 | Signature changed, wrong enrolled key/purpose, or unknown identity | Typed rejection; no satisfied check; INDETERMINATE if required |
| A14 | Replayed observation/receipt across attempt, transaction, phase, nonce or target | Reject binding/replay; valid exact retry is idempotent |
| A15 | Actor supplies a foreign contract hash or changes approved bytes | Freeze/admission denied; cannot control acceptance |
| A16 | Window not elapsed, insufficient samples, excessive gap, or mixed artifact | INDETERMINATE; no false durability success |
| A17 | Primary check explicitly fails while both invariants pass | DISPROVEN |
| A18 | Missing evidence and a separate valid mandatory invariant FAIL | DISPROVEN; known failure precedence |
| A19 | Duplicate JSON keys, invalid Unicode, NaN, unsupported version/fields, excessive nesting/size | Parser/schema rejection before mutation or signing |
| A20 | Evidence file changed after envelope creation, or hash supplied without bytes | Reject EVIDENCE_HASH_MISMATCH or EVIDENCE_MISSING |
| A21 | Illegal transition, wrong submitting principal, stale expected-head or concurrent duplicate ID | Atomic rejection/one winner; history remains valid |
| A22 | Ledger record reordered, edited, deleted, truncated or restored to an old checkpoint | History invalid; no acceptance; typed integrity error retained |
| A23 | Owner risk acceptance after DISPROVEN | Separate signed RISK_ACCEPTED event; verdict bytes and normal acceptance eligibility unchanged |
| A24 | Recovery target has independently authorized newer changes | Stale restoration precondition denied; no clobbering |
| A25 | Recovery reports success but evidence unavailable through deadline | Child INDETERMINATE; parent RECOVERY_FAILED with unverified-restoration reason |
| A26 | Same pinned inputs and clock, different prose/order of equivalent input delivery | Same verdict/reasons; event chronology and conflicting evidence rules preserved |
| A27 | Trusted-clock discontinuity or future observation beyond tolerance | INDETERMINATE; no accepted window |
| A28 | Valid frozen contract changed by authority runtime or evaluator key used for verdict signing | Denied binding/purpose; valid authority-signed packet control passes |

## Execution layers after review

Unit checks exercise schema parsing, official crypto vectors, guard functions, deterministic aggregation and replay. Adversarial checks exercise tampered/replayed inputs, race/crash behavior, malformed payloads and hostile histories within owned temporary fixtures. None target third-party systems.

Installed-package acceptance exercises the wheel/CLI in a fresh environment with real key pairs, file bytes, durable stores, subprocess interruption and restart. Keys are ephemeral and private; receipts retain public identity, hashes, test IDs, observations and verdicts without secret material. A fixture-built deployment receipt is labeled synthetic.

The later integration gate performs actual resource/key access checks under separate identities, live application requests, protected evaluator access denial, deployed-artifact read-back, a fixed observation window and actual independently verified baseline redeployment. It cannot be replaced by simulated success receipts or unit tests.

## Measurements

- False closure: PROVEN on a known failed/unknown mandatory obligation; target zero in this declared suite.
- Valid control acceptance: every declared valid case must pass; target all, preventing reject-all behavior.
- Binding/tampering detection: detected inadmissible cases divided by introduced cases, with typed reasons.
- Determinism: identical terminal verdict/reasons for identical pinned inputs/time.
- Recovery: verified scoped restoration divided by authorized attempted recoveries; unverified and failed separate.
- Crash safety: accepted histories and reconciled outcomes after every exercised interruption point.
- Time/cost: kernel evaluation duration, evidence bytes and crypto operations for this bounded workload; no universal scaling claim.

For each executed check retain scenario ID, package/commit hashes, contract/policy/evaluator hashes, actual outcome, timestamps, public identities and evidence digests. Report Worked or Failed only for actual execution. Report Blocked with the attempted check and exact blocker when execution cannot proceed. Never present this planned matrix as passed.
