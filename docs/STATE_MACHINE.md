# Append-only lifecycle and deterministic decisions

Status: approved design with an implemented offline kernel in src/closure_engine/ledger.py. State is derived by replaying validated events, never edited as a mutable status field.

## Normal lifecycle

```text
DRAFT -> APPROVED -> FROZEN -> BASELINED -> EXECUTING
      -> VERIFYING -> OBSERVING
      -> PROVEN | DISPROVEN | PARTIALLY_PROVEN | INDETERMINATE
      -> ACCEPTED | RECOVERY_REQUIRED
      -> RECOVERED | RECOVERY_FAILED
```

This is a lifecycle overview, not permission for every displayed branch. The legal edges and guards below control execution. Technical verdict, operational decision and recovery status are distinct projections of one ordered event history.

| Event/edge | Guard and authorized submitter |
| --- | --- |
| DRAFT -> APPROVED | Owner signs exact proposed contract hash/version; enrolled approver identity |
| APPROVED -> FROZEN | Authority validates approval, schema, enrollment/policy pins and all criteria; frozen bytes unchanged |
| FROZEN -> BASELINED | Admissible baseline covers every declared precondition and protected resource; qualified observers |
| BASELINED -> EXECUTING | Broker records authorized action intent before side effect with expected baseline/current-state binding |
| EXECUTING -> VERIFYING | Bound broker receipt or reconciliation establishes action result; unknown effects cannot advance |
| VERIFYING -> OBSERVING | Required immediate checks admitted and successful; window starts from trusted deployment/observation anchor |
| OBSERVING -> PROVEN | All mandatory outcome, invariant, deployment and window requirements met with admissible evidence |
| Active frozen state -> DISPROVEN | Qualified trusted observation proves a mandatory failure; authority emits failure packet immediately |
| Active frozen state -> INDETERMINATE | Deadline, interruption, unavailable observation, or unresolved integrity/admissibility prevents conclusion |
| VERIFYING -> PARTIALLY_PROVEN | A declared stage is proved and trusted evidence establishes known non-completion of another stage; no mandatory invariant failure or required unknown |
| PROVEN -> ACCEPTED | Authorized acceptance event referencing exact packet hash; no implicit owner approval |
| Any terminal verdict -> RECOVERY_REQUIRED | Frozen recovery policy/authorized request says restoration or reconciliation is necessary; no new side effect merely because evidence is missing |
| RECOVERY_REQUIRED -> RECOVERED | Linked recovery transaction proves scoped restoration, including its invariants and observation requirements |
| RECOVERY_REQUIRED -> RECOVERY_FAILED | Recovery fails a restoration requirement or deadline expires without required verification |

Missing evidence before effects begin yields indeterminate and an escalation decision; it does not automatically authorize rollback. Unknown state after possible effects requires reconciliation and recovery-required handling under the approved policy. A no-deployment receipt may enter VERIFYING solely to evaluate confirmed non-completion; it cannot enter OBSERVING as a successful deployment.

## Verdict precedence

Only admissible observations enter outcome evaluation. Invalid submissions are retained as rejection events, not evidence of a passed check or an automatic accusation against the actor.

1. Any admissible mandatory invariant FAIL, qualified evaluator-tamper finding, or mandatory functional FAIL yields DISPROVEN. It outranks successful primary checks and missing unrelated evidence.
2. Without a known mandatory failure, unresolved required evidence, ambiguous conflicting observations, unfinished observation window, unknown execution state, or unavailable trusted inputs yields INDETERMINATE.
3. PARTIALLY_PROVEN requires positive proof of a declared completed stage, authenticated known non-completion (such as NOT_DEPLOYED) of a declared stage, and complete required invariant evidence for the effects that actually occurred. Absence of a deployment receipt is INDETERMINATE. Stage status does not relax mandatory functional/invariant rules.
4. PROVEN requires every declared mandatory obligation to pass, including deployment binding and completed window. Optional checks never substitute for mandatory checks.

Per-obligation outcomes are PASS, FAIL, UNKNOWN, or confirmed NOT_COMPLETED where the contract permits that stage status. A semantic FAIL cannot be relabeled NOT_COMPLETED to escape disproven precedence. A signed valid FAIL is not canceled by a later PASS inside the same attempt; conflicting claims without a resolvable authoritative ordering remain indeterminate. Evaluate terminal results at a declared deadline or explicit authorized stop; do not finalize every intermediate incomplete sample.

The partial/deployment rule resolves the supplied matrix's tension with "missing required evidence produces INDETERMINATE." It must be reviewed before code.

## Transition invariants

- Frozen contract bytes and accepted evidence are immutable. Corrections create a new linked version/transaction and fresh approval.
- Every event binds transaction, contract, attempt, sequence, expected previous hash, identity and policy version. Wrong caller capabilities and illegal edges reject atomically.
- Only one event wins an expected-head append. Exact duplicate submission is idempotent; altered reuse of an ID is rejected.
- An action receipt is not independent outcome evidence. A deployment receipt alone cannot prove behavior.
- One immutable technical verdict packet closes each attempt. Further investigation or later regression creates a linked attempt/transaction; it never overwrites the original verdict.
- The authority uses a pinned evaluation policy, enrolled trust snapshot and operator-supplied evaluation time. Replaying those identical inputs reproduces the verdict and reason codes.
- No verdict depends on model prose, environment-selected scripts or random sampling. Enrollment pins and evaluation time are explicit operator/authority inputs; the offline kernel has no independent physical clock. Ledger event times and transaction evaluation times cannot regress. A compromised authority clock can still misstate a recovery deadline; independent time custody is a production gate.
- Persist intent before side effects. A crash between action and receipt requires reconciliation; an unresolved action is not blindly reissued.
- ACCEPTED requires PROVEN. A human who accepts risk on another verdict emits a separate RISK_ACCEPTED event; the technical result and normal acceptance eligibility stay unchanged.

## Recovery

Recovery is a linked child transaction with its own approved/frozen contract, hash, authority envelope, observed current state, target baseline, evidence and closure packet. The parent remains disproven/partial/indeterminate as originally recorded.

RECOVERED means the child is PROVEN and its specific restoration checks pass. Broker-reported rollback success is insufficient. Missing recovery evidence yields child INDETERMINATE while pending; at the recovery deadline the parent's outcome becomes RECOVERY_FAILED with an unverified-restoration reason, not a fabricated functional FAIL.

Restoration is scoped: restore protected application state while preserving ledger history and separately authorized newer changes. If current state diverges from the approved recovery precondition, stop and escalate. Retry/compensation requires its declared authority; it is not granted by a failure verdict.
