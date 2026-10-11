# Phase 0 implementation plan

Status: owner approved design commit 7e7a503 on 2026-10-11; M1-M5 implementation is authorized. See APPROVAL.md. Milestones are acceptance gates; observed results are recorded separately.

## Scope and architecture

Build a deterministic Python kernel with ports for evidence reads, ledger append, time, enrollment and signing. Pure lifecycle and verdict rules have no network, model, deployment or filesystem side effects. Adapters provide local durable storage and real cryptographic operations. Separate runtime identities remain a deployment requirement; importing separate Python modules does not enforce isolation.

Target Python 3.12 on this host; declare and test any additional supported versions explicitly. Select maintained JSON Schema, JCS and Ed25519 libraries after review, pin dependencies, and run official vectors rather than writing custom cryptography. The planned vocabulary has no general-purpose script execution or model-generated evaluation code.

Version one has one repository, bounded patch, deployment target, verifier path and recovery mechanism. Phase 0 consumes synthetic signed records and real temporary artifacts. Phase 1 will exercise one local disposable application after the kernel gates pass and the owner selects the concrete defect and isolation arrangement. Production remains excluded.

## Proposed repository tree

The original proposed tree is retained below as a design reference. Implementation uses a smaller flat Python package: protocol.py, crypto.py, contracts.py, store.py, verdicts.py, ledger.py, recovery.py, demo.py and cli.py. Committed schemas live under src/closure_engine/schemas/v1; tools/build_schemas.py regenerates them. Tests cover the same domain boundaries without unnecessary package nesting. The demo is an explicit offline fixture; deployment/identity adapters remain future work.

```text
agentic-closure-engine/
  README.md
  AGENTS.md
  .gitignore
  .gitattributes
  pyproject.toml
  dependency lock file
  schemas/v1/
    closure-contract.schema.json
    approval.schema.json
    evidence-envelope.schema.json
    action-receipt.schema.json
    ledger-event.schema.json
    closure-packet.schema.json
    risk-acceptance.schema.json
    recovery-contract.schema.json
  src/closure_engine/
    domain/
      contracts.py
      lifecycle.py
      admissibility.py
      verdicts.py
      recovery.py
      events.py
    application/
      transactions.py
      ports.py
    adapters/
      schemas.py
      canonical_json.py
      ed25519.py
      local_ledger.py
      evidence_store.py
      trusted_clock.py     # planned production adapter; not a Phase 0 implemented module
    cli.py
  tests/
    unit/
    adversarial/
    acceptance/
    vectors/
  examples/v1/
    bounded-change-contract.json
    recovery-contract.json
  tools/
    verify-phase0.ps1
  docs/
    IMPLEMENTATION_PLAN.md
    TRUST_BOUNDARIES.md
    STATE_MACHINE.md
    EVIDENCE_PROTOCOL.md
    ACCEPTANCE_MATRIX.md
  evidence-runs/                 # generated, ignored
```

## Milestones and gates

| Milestone | Implementation | Required check and retained evidence |
| --- | --- | --- |
| M0: design review | This package and reviewed commit | Owner reviews trust domains, verdict precedence, lifecycle and evidence protocol; record approval without inventing it |
| M1: contract and crypto | Versioned schemas, bounded parser, JCS hashing, approvals, enrollment, Ed25519 | Official serialization/signature vectors, malformed and unknown-version rejection, approval/freeze binding, deterministic hash receipt |
| M2: lifecycle and ledger | Event replay, legal transitions, expected-head concurrency, atomic append, content-addressed evidence | Crash/restart, duplicate append, concurrent writers, corruption and stale-checkpoint tests with event-chain receipts |
| M3: observations and verdict | Admissibility, time/window checks, mandatory precedence, immutable packets | All verdict scenarios and valid controls; permutation/replay determinism with fixed clock and pinned policy |
| M4: recovery | Linked recovery contract, original-verdict preservation, restoration observations | Verified restoration, falsely reported restoration, interrupted recovery, out-of-envelope compensation tests |
| M5: shipped Phase 0 | Wheel, CLI, offline verification script | Build/install in a fresh environment and execute real signatures, temporary artifact observations and crash cases through CLI; export results and hashes |
| M6: later integration | One disposable target, broker and protected verifier under separate identities | Actual deployed behavior, two protected invariants, fixed window and actual verified rollback; separate owner-approved scope |

Write behavioral red tests before each M1-M4 implementation. The evaluator/test expectation source is independently controlled for final acceptance. Candidate code and candidate-maintained tests are not sufficient for that gate.

M5 must identify how many checks used real crypto, real I/O and subprocesses versus synthetic records. It must not describe synthetic deployment receipts as a deployed application. M6 must test actual cross-identity denials; no account creation or ACL modification is authorized by this design package.

## Proposed first real transaction, after Phase 0

Use a tiny disposable local HTTP application with a documented input-normalization defect, selected and baselined before the actor patch. Fix one endpoint. Protect a second endpoint's behavior and read-only configuration/state. The broker deploys a content-addressed package to one local target; the verifier checks live requests against the exact artifact and a frozen test bundle. Observe for 60 seconds with a contract-defined sampling cadence. Recover by redeploying the retained baseline artifact, then verify both behavior and protected state.

The endpoint, defect, baseline artifact, operating identities and probe cadence must be concrete before freezing that transaction. This is a proposed fixture, not a statement that a defect or deployment already exists.

## Acceptance boundary

Phase 0 finishes when the installed kernel passes the planned positive/adversarial matrix and reproduces its verdicts from retained inputs, event history and trusted policy. It does not certify a live authority boundary. Phase 1 finishes only after its real cross-identity, deployed-behavior, window and rollback checks pass.

Review approval releases M1-M5 only. Agent-wire, SelfConnect, WRAITH/CRUCIBLE adapters and production integrations remain later work.
