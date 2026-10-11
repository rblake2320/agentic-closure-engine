# Contract and evidence protocol v1 proposal

Status: v1 offline protocol implemented in src/closure_engine, with packaged schemas/v1 JSON Schemas. Fixture keys are generated only in memory; production enrollment/key custody is not provisioned.

## Serialization and signatures

Use versioned JSON Schema documents with explicit format validation and rejection of unknown fields/versions. Draft 2020-12 separates format annotation and assertion; implementation must deliberately enforce the needed timestamp/identifier formats. [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)

Hash UTF-8 canonical JSON using SHA-256. Use JCS rather than assuming ordinary sorted JSON is interoperable; reject duplicate keys, invalid Unicode, non-finite numbers and out-of-range integers. v1 forbids floating-point protocol quantities and uses bounded integers for durations/counters. Preserve string content without Unicode normalization. [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)

Use an established Ed25519 implementation and official test vectors. Each signed message includes a distinct purpose/version prefix and the canonical payload; a signature cannot be moved between approval, evidence, receipt, ledger event, risk event or verdict packet. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)

Envelope structure separates a signed payload from key ID, algorithm and signature. The signed payload includes identity, key ID, purpose and version as well; signature metadata must match it. Hash the entire canonical signed object when referencing a packet/observation; signed payload hashes are separately labeled to avoid recursive signature fields. Public keys come only from the operator-approved enrollment snapshot, never the submitted envelope.

## Frozen contract

Proposed required groups:

- Identity: schema/protocol version, contract ID/revision, parent/superseded contract, transaction ID, approved repository identity and exact baseline commit/tree hash.
- Authority: allowed principal/action/resource/argument sets, target identity, budgets/expiry, stop rules, approved recovery capability. No shell commands or executable expressions in criteria.
- State: baseline evidence requirements, intended delta, allowed write set, protected resources, mandatory functional checks and mandatory invariants.
- Acceptance: declared stages, required evidence type/check IDs, evaluator bundle hash, allowed observer identities and signing purposes, artifact-binding rules, verifier-policy hash and trust-snapshot hash.
- Time: overall deadline, evidence max age, maximum clock skew, observation duration, start anchor, sample interval/max gap/minimum samples, recovery deadline.
- Recovery: exact baseline restoration scope, precondition/current-state binding, approved single recovery mechanism, protected non-restoration state, independent restoration checks.

Contract approval is a separate owner-signed object binding the exact canonical contract hash and enrollment/policy snapshot. Freeze never inserts fields into the already approved bytes. Artifact bytes may not exist at freeze: the contract fixes the permitted build/source relationship; a signed build/deployment receipt later binds the exact selected artifact hash to the transaction/attempt. Every observation then references that same artifact. An artifact switch requires a new approved attempt rather than relaxing equality.

## Evidence envelope

The user's example becomes a signed payload with these bindings:

| Field group | Required binding |
| --- | --- |
| Routing | Protocol version, transaction ID, attempt ID, phase, unique observation/receipt ID, challenge nonce |
| Subject | Contract hash, actual artifact hash, repository/build source, target identity, deployment/action ID |
| Check | Check ID, evaluator bundle hash, evaluator policy version, result and machine reason code |
| Identity | Enrolled observer identity, key ID, signing purpose; capability authorized for that check |
| Time | UTC observed-at timestamp, trusted custodian received-at timestamp, expiration/max-age policy; authority evaluation time |
| Evidence | Digest, media type, size and custodian reference for immutable evidence bytes |
| Lineage | Baseline ID where applicable, related action/observation hashes and recovery parent |

Custodian receive time is in a separately signed ingestion receipt; the verifier cannot self-assert it. Check results are PASS/FAIL/UNKNOWN; an action/stage receipt may additionally assert NOT_DEPLOYED or NOT_COMPLETED for narrowly defined stage outcomes. Broker receipts never satisfy a check requiring an independent verifier.

Schema validity is necessary, not sufficient. Admission validates signature, enrollment/purpose/capability, all subject bindings, evidence bytes against digest, event lineage, freshness and trusted-clock constraints. Missing evidence bytes cannot pass because a digest was supplied.

Foreign, expired, future-dated, wrongly signed, wrong-artifact or replayed evidence is inadmissible and recorded with a typed reason. If this leaves a required obligation unanswered, the verdict is indeterminate unless another admissible mandatory failure already establishes disproven.

## Replay, windows and reproducibility

Challenge nonces are authority-issued and phase/check/attempt-bound. IDs and nonces are consumed atomically with evidence admission; exact transport retries return the original receipt, never a second satisfied check. Reusing bytes in another transaction/window or changing payload under an existing ID is rejected.

An observation window begins at the frozen trusted anchor after deployment is bound. All required samples must lie in the window, meet min-count/max-gap/cadence rules, refer to the same artifact/target and be fresh at evaluation. A single PASS plus elapsed wall time is insufficient. Validate max age against window duration at freeze so the contract can actually be satisfied. Wall-clock jumps beyond tolerance stop acceptance; deterministic tests inject a fixed trusted clock.

The packet includes contract/approval hashes, artifact/baseline/build/deployment bindings, policy/evaluator/trust snapshot hashes, accepted and rejected evidence references, per-obligation outcomes, exact evaluated window/time, terminal verdict/reasons, recovery disposition, issuer identity and signature. Referenced evidence/ledger heads are the inputs before the closure event, avoiding a circular packet/event hash dependency.

## Ledger and evidence custody

Event payloads include sequence, previous-event hash, transaction/attempt, caller identity, event type, frozen contract hash and immutable object references. A local SQLite adapter is proposed for atomic append and unique IDs; durable write mode, rollback/truncation detection against independent checkpoints, and startup reconciliation must be tested. Storage API append-only behavior and hash chaining are separate from OS custody guarantees.

Content-addressed evidence objects use atomic non-replacing creation, fsync and read-back digest verification. Orphan pending files are ignored, not accepted as evidence; missing objects invalidate the affected obligation. No observation byte edits, silent history repair, duplicate-event counting, or evaluator-selected trust anchors.

The implemented baseline obligation reads and hashes the retained baseline artifact. BASELINED lifecycle events additionally require a complete protected-resource manifest and all referenced bytes. Recovery approval and its observation window must follow the parent's verdict; old observations cannot satisfy restoration.

The public CLI accepts offline-fixture bundles only. Evaluation time and enrollment are explicit operator inputs; this is not an authenticated multi-user runtime service and it performs no production operations.

New ledgers use SQLite DELETE rollback journaling with synchronous=FULL for the bounded single-writer deployment. The initial WAL configuration produced one Windows/Python 3.13 crash-reopen I/O failure, followed by a passing rerun. That dependency/OS interaction is contained by avoiding shared-memory WAL in new stores; its exact underlying cause is not asserted. No existing database is silently migrated or repaired. Crash tests execute three independent killed-writer runs per environment.
