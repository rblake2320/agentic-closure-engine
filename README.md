# Agentic Closure Engine

Status: Phase 0 design proposed for owner review. No implementation has been written.

The planned product evaluates whether a specific authorized state transition has enough admissible, independent evidence for acceptance. AI may propose contracts and changes; frozen contracts and deterministic rules control technical verdicts.

Version one is bounded to one repository, one change, one deployment target, one independent verification path, and one recovery mechanism. Phase 0 implements the offline closure kernel after design review. A real deployment demonstration and operating-identity isolation are later gates, not claims made by the kernel.

## Review package

- [Implementation plan and proposed repository tree](docs/IMPLEMENTATION_PLAN.md)
- [Trust domains, authority and threat model](docs/TRUST_BOUNDARIES.md)
- [Append-only lifecycle and verdict rules](docs/STATE_MACHINE.md)
- [Contract, evidence, signature and freshness protocol](docs/EVIDENCE_PROTOCOL.md)
- [Acceptance and adversarial matrix](docs/ACCEPTANCE_MATRIX.md)

The owner requested: "Produce an implementation plan and repository tree first; do not write code until the trust boundaries and state-transition invariants have been reviewed." This repository currently contains the review package only. Approval must reference the reviewed commit; corrections require a revised review package.

## Decisions proposed for review

1. Four workflow domains with separately controlled identities; operator-controlled trust roots and ledger custody are supporting infrastructure, not actor authority.
2. Mandatory-invariant failure outranks successful task checks. Missing required evidence is indeterminate. Partial proof requires authenticated known non-completion, not an absent receipt.
3. Immutable technical verdicts, separate acceptance events, and a separately verified recovery transaction. Risk acceptance never changes a verdict.
4. Protected public-key enrollment, external ledger checkpoints, and versioned evaluator/authority-policy hashes. A signature alone is not an outcome proof.
5. An offline Python kernel with standards-based serialization and real signatures, followed by installed-package acceptance tests. No production integration or host-account provisioning in Phase 0.

No remote repository, production credentials, deployment, account changes, or service integrations have been created.
