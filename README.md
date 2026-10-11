# Agentic Closure Engine

Phase 0: an offline deterministic closure kernel. The owner approved design commit 7e7a503 on 2026-10-11; implementation is authorized and recorded in [APPROVAL.md](docs/APPROVAL.md).

The kernel evaluates whether a specific authorized state transition has enough admissible, independent evidence for acceptance. AI may propose contracts and changes; frozen contracts and deterministic rules control technical verdicts. AI does not participate in the verdict path.

Version one is bounded to one repository, one change, one deployment target, one independent verification path, and one recovery mechanism. Phase 0 implements schemas, canonical hashing, signatures, immutable contracts, bound evidence, deterministic verdicts, an append-only lifecycle/ledger and independently verified recovery. Demo deployment/behavior records are synthetic; signatures, artifact reads, ledger persistence and subprocess interruption are real. The CLI labels that distinction. Operating-identity enforcement and actual target credentials are Phase 1 gates.

## Design

- [Implementation plan and proposed repository tree](docs/IMPLEMENTATION_PLAN.md)
- [Trust domains, authority and threat model](docs/TRUST_BOUNDARIES.md)
- [Append-only lifecycle and verdict rules](docs/STATE_MACHINE.md)
- [Contract, evidence, signature and freshness protocol](docs/EVIDENCE_PROTOCOL.md)
- [Acceptance and adversarial matrix](docs/ACCEPTANCE_MATRIX.md)

The owner requested a review package before code, then approved that package with "do it." The approved design remains available at commit 7e7a503. Corrections to frozen runtime contracts require a new version and approval.

## Implementation boundaries

1. Four workflow domains with separately controlled identities; operator-controlled trust roots and ledger custody are supporting infrastructure, not actor authority.
2. Mandatory-invariant failure outranks successful task checks. Missing required evidence is indeterminate. Partial proof requires authenticated known non-completion, not an absent receipt.
3. Immutable technical verdicts, separate acceptance events, and a separately verified recovery transaction. Risk acceptance never changes a verdict.
4. Protected public-key enrollment, external ledger checkpoints, and versioned evaluator/authority-policy hashes. A signature alone is not an outcome proof.
5. An offline Python kernel with standards-based serialization and real signatures, followed by installed-package acceptance tests. No production integration or host-account provisioning in Phase 0.

Private repository: https://github.com/rblake2320/agentic-closure-engine

Progress tracker: https://rob47595-1791122756383.atlassian.net/browse/KAN-129

## Run

```powershell
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe --require-hashes -r requirements.lock
uv pip install --python .venv\Scripts\python.exe --no-deps -e .
.venv\Scripts\closure-engine.exe demo --output evidence-runs\my-demo
```

The demo output must be a new/empty directory. Fixture private keys remain in memory and are never exported. Public contract, approval, evidence, signed packets and checkpoint are retained.

Recompute the verdict using the exact `evaluated_at` emitted by demo:

```powershell
.venv\Scripts\closure-engine.exe evaluate-run --bundle evidence-runs\my-demo\run.json --trust evidence-runs\my-demo\trust.json --store evidence-runs\my-demo\evidence --at 2026-10-11T12:01:00.000Z --require-proven
```

The fixture uses a fixed clock. Without `--require-proven`, a successfully computed adverse verdict exits zero; with it an adverse verdict exits 3. Invalid input/storage exits 2 with a typed error.

Build and test the installed wheel in a fresh environment:

```powershell
powershell -NoProfile -File tools\verify-phase0.ps1 -Python .venv\Scripts\python.exe
```

The script installs hash-pinned registry dependencies, builds a wheel, asserts imports come from its fresh site-packages, runs the suite against that installed package and independently replays eleven signed fixture scenarios. It retains public receipts, JUnit, wheel hash, package inventory and signed packets under the printed output directory. Python 3.12 and 3.13 are the CI matrix.

[Laya scope decision](docs/LAYA_ADVISORY.md): left out of Phase 0; no inference executed or weights downloaded.

No production credentials, deployments, account changes, or agent-wire/SelfConnect/WRAITH/CRUCIBLE integrations are enabled.
