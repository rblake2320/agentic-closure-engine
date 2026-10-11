# Agentic Closure Engine

ACE is an operating authority for evidence-backed completion. It stages a real artifact,
freezes an owner-approved contract, deploys through a credential-holding broker, reads the
actual target independently, and signs a deterministic verdict. Recovery has its own contract
and verification. An AI model is never part of the verdict path.

The 0.3 product includes a persistent operating CLI, authenticated HTTP API and browser console,
separate role services, protected evidence custody, public audit replay, and encrypted cold
backup with independently anchored restoration. Agent Work Ledger is a separate optional
product; it consumes ACE verdicts and cannot change them.

## Start an installation

With Docker Desktop running, supply an operator-controlled target profile:

```powershell
powershell -NoProfile -File tools/start-product.ps1 -TargetProfile C:/path/to/target-profile.json
```

Open `http://127.0.0.1:8782/` and use `.runtime/operator.token`. The command creates persistent
role identities once, exports no signing keys, and preserves them on restart. The console
starts with recorded transactions only. Review the desired primary values, protected checks
and scope before approving; freezing prevents changes to that acceptance contract.

A real JSON publishing target is also shipped. To operate it, supply its initial content as
`-PublisherArtifact C:/path/to/initial-artifact.json`, and enroll `http://publisher:9002` in the
profile. Its contents are actually persisted and served at `http://127.0.0.1:8784/`.
No test outcomes or success verdicts are seeded. Other applications implement the
[target protocol and probes](docs/OPERATIONS.md).

Use `tools/stop-product.ps1` to stop without deleting state. See
[operating instructions](docs/OPERATIONS.md) for the profile format, CLI, credentials,
acceptance, reconciliation, recovery, backups and separate AWL integration.

## Authority boundaries

| Service | Credentials and responsibility |
| --- | --- |
| Actor | Propose artifacts and recovery; its own signing identity |
| Owner | Approve frozen criteria and separately accept proven outcomes |
| Broker | Scoped target credential, preconditions and durable action intents |
| Verifier | Independent target read-back and protected-state observations |
| Authority | Deterministic evaluation and technical verdict signing |
| Custody | Evidence and ledger admission, ingestion and checkpoints |
| Gateway | Authenticated orchestration; no signing keys |

The self-hosted services use separate Linux UIDs and private mounts. Live services have
readonly root filesystems, dropped capabilities, no Docker socket and no other role's key.
The console and optional publisher expose loopback ports only; actor, broker and verifier can reach enrolled targets.
The Docker administrator and enrollment operator remain trusted administrators. Native CLI
mode supports operator-owned installations; directories alone are not privilege isolation.

Missing evidence is INDETERMINATE. An authenticated mandatory failure is DISPROVEN, including
when a primary check succeeds. An owner-signed opt-in under policy v3 permits PARTIALLY_PROVEN
only for independently confirmed non-deployment with the unchanged baseline; it never excuses
a failed invariant. Policy v2 packets replay under their original rules. Signed packets must
be independently reconstructable and admitted to the ledger before downstream acceptance.

## Validation and review

```powershell
python tools/verify_phase0.py --output evidence-runs/new-installed-check
python tools/verify_container_boundaries.py --output evidence-runs/container-check.json
```

The installed gate builds a new wheel, uses a fresh environment, disables pytest source imports,
and retains wheel hashes, origins and JUnit. It includes kernel regressions and actual runtime
HTTP/CLI operations. The eleven legacy fixture scenarios remain kernel regression checks;
they are not the product demonstration. The live deployment, disagreement and verified
restoration have separate receipts in [observed validation](docs/VALIDATION.md).

[State machine and policies](docs/STATE_MACHINE.md) · [Trust boundaries](docs/TRUST_BOUNDARIES.md) ·
[Evidence protocol](docs/EVIDENCE_PROTOCOL.md) · [Acceptance matrix](docs/ACCEPTANCE_MATRIX.md)

Repository: https://github.com/rblake2320/agentic-closure-engine

Tracking: KAN-130 (kernel hardening), KAN-131 (operating authority), KAN-129 (historical foundation).
The current product branch and draft review are tracked in GitHub; merge requires the release gates.
