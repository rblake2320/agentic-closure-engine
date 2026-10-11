# Trust boundaries and threat model

Status: proposed. This document defines requirements; no OS or credential isolation has been provisioned.

## Principals and capabilities

| Workflow domain | May do | Must not possess or modify |
| --- | --- | --- |
| Actor | Draft contracts, propose patch bytes, request narrowly named actions | Deployment credentials; verifier or authority private keys; protected evaluator; ledger/evidence custody; approved policy |
| Enforcement broker | Validate request against frozen authority envelope, perform scoped operation, sign action receipts | Closure-signing key; verdict policy edits; evaluator edits; permission to assert the independent outcome |
| Verifier | Read deployed state, execute operator-installed checks, sign observations with its own verifier key | Actor workspace write access; broker deployment credentials; closure-signing key; evaluator update permission |
| Closure authority | Admit evidence, run pinned deterministic rules, append decisions, sign closure packets | Artifact/deployment mutation; observation/evaluator mutation; verifier private key |

The verifier owns an observation-signing key, not a verdict-signing key. Signing authority is bound to enrolled identity and purpose; payload-provided identities are never self-enrolling.

An operator/installer controls public-key enrollment, evaluator installation, authority policy installation, and storage custody. It is an explicit trusted administrative root, separate from the four workflow domains. Its ledger custodian exposes authenticated append/read operations; workflow domains cannot open mutable ledger storage directly. Compromise of this root is a material trust failure. Four named processes under the owner's same administrative token do not satisfy this model.

## Protected resources

| Resource | Custody and access requirement |
| --- | --- |
| Actor proposals | Actor-writable staging; broker reads exact content by hash; treat paths and metadata as untrusted |
| Deployment target | Broker alone can change the allowed target; verifier read/probe only; actor and authority denied |
| Evaluator bundle | Operator-installed immutable version; verifier read/execute only; actor/broker/authority denied writes |
| Contract approval | Owner enrollment key signs exact contract hash; correction requires new approval/version |
| Observations/evidence | Verifier or broker submits new content-addressed objects; no workflow principal can replace accepted bytes |
| Ledger | Custodian append API with legal caller/event capabilities; independent checkpoint custody detects rollback/truncation |
| Private keys | Purpose-specific stores readable only by the operating principal; no shared environment, folder or copied secrets |
| Authority executable/policy | Operator-installed pinned version; authority runtime reads but cannot update it |

The authority may submit append-only verdict events; that does not grant edit/delete access to earlier evidence. Hash chains detect changes relative to a trusted head; they do not prevent a storage administrator rewriting a complete history. External checkpoints and independent custody are required for that threat. Offline Phase 0 will exercise the mechanism with temporary stores and separately retained heads, with no claim of resistance to a malicious host administrator.

The broker validates exact resource, operation, artifact, arguments, budget, expiry and transaction identity. It performs the side effect itself. It must not give the actor a credential or return an executable permission token redeemable outside that bound operation. The future isolation gate must establish that the actor lacks alternative target write access.

## Threats, controls and checks

| Threat | Required control | Planned acceptance check |
| --- | --- | --- |
| Actor bypasses broker | Scoped target credentials plus OS/target denial | Future real cross-identity write/deploy denial; actor proposal remains allowed |
| Evaluator modification or candidate test weakening | Operator-pinned evaluator manifest and protected execution identity | Tamper signal rejects/halts candidate; valid evaluator control passes |
| Verifier takes discretion over acceptance | Observations only; immutable deterministic authority rules | Same observations/policy/time give identical verdict despite prose variations |
| Forged identity or observations | Enrolled purpose-bound keys, full payload signatures | Wrong key, purpose, transaction and signature rejected |
| Old or foreign evidence | Contract, artifact, target, attempt, freshness and nonce binding | Replay, stale and cross-target cases rejected |
| Observe A, deploy B | Broker content-addressed install plus verifier artifact observation | Hash mismatch is inadmissible; no success packet |
| Collateral effects | Named protected resources and independently observed invariants | Main task passes while one mandatory invariant fails: disproven |
| Interrupted side effect | Durable intent before action; reconciliation before retry | Unknown result produces indeterminate plus recovery required, never blind replay |
| Ledger rewrite or truncation | Append API, sequence/head checks, independent checkpoints | Mutated/reordered/deleted/truncated history cannot yield valid accepted packet |
| Recovery clobbers newer legitimate state | Recovery authorization, expected current-state binding and scoped restoration | Concurrent change rejects stale recovery request |
| Operator risk override hides failure | Separate signed risk event | Original technical packet and verdict remain byte-identical |
| Malicious input consumes verifier resources | Fixed schema, size/depth/item limits; no arbitrary executable criteria | Oversized, duplicate-key and unknown-check inputs fail closed |

A verifier signature authenticates the observer's claim. The frozen checks and independent observations establish the declared outcome. A compromised enrolled verifier can lie; Phase 0 detects binding/integrity failures, not arbitrary fabricated reality from an otherwise trusted principal. Coverage is limited to explicitly named resources, targets, invariants and time windows.

## Review and later isolation gate

The owner reviews these boundaries before implementation. Before any live demonstration, independently test resource and key access under each actual operating identity, including both permitted controls and prohibited accesses. Retain exact denied resource, principal and platform response. Fixture-only denial records cannot satisfy that gate. OS administrator/kernel compromise and physical-world consequences are outside this bounded first deployment model and must not be claimed as covered.
