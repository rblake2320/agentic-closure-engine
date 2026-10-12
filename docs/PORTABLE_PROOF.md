# Portable closure proofs

The authenticated `GET /api/v1/transactions/{id}/bundle` download includes the frozen contract,
owner approval, run binding, observation/ingestion records and deployment receipts. Its
`portable` member adds the public enrollment, owner-approved evaluator definitions (including
expected and restoration values), known kernel policy version identifiers, complete signed
global ledger history, signed custodian checkpoint and exact content-addressed evidence bytes.
The custody audit-export response also supplies the public enrollment; it contains public
Ed25519 keys and role assignments, never private signing keys or bearer credentials.

The complete global history is necessary because a transaction's events are linked through
intervening events for other transactions. This export explicitly refuses a concurrently
changing ledger snapshot (`EXPORT_SNAPSHOT_CHANGED`); retry the read. Downloads contain
application evidence, artifacts and probe locations and should be handled as sensitive project
data even though no signing or deployment credential is exported.

## Verification without the original server

Install the ACE wheel on a separate machine, save the downloaded JSON and run:

```powershell
python -I -m closure_engine.runtime.portable --bundle downloaded.json `
  --expected-trust-hash sha256:<operator-held-enrollment-digest> --require-proven
```

Obtain the enrollment digest independently from the deployment operator or an independently
authenticated enrollment publication. Reading a key or its digest out of this same downloaded
bundle is not an independent trust anchor. The verifier requires the pin as an explicit argument
and refuses an enrollment replacement even if the attacker recomputes every local digest.

The command needs no bearer token, runtime folder, private key, target connection or running
ACE service. It verifies every embedded evidence digest, frozen approval, event and checkpoint
signature; reconstructs the ledger with the existing `Ledger.import_history`; and uses the
existing `replay_packet`/deterministic verdict evaluator. It additionally checks that the readable
evaluator expectations and legacy run inputs exactly match their authenticated retained inputs.
There is no new verdict algorithm or AI judge.

For an acceptance gate, also bind the caller's independently expected subject using
`--expected-transaction`, `--expected-contract-hash` and `--expected-artifact-hash`. These refuse
substitution of an otherwise genuine signed proof for a different task or artifact. Without those
arguments the command reports which signed subject it verified; it does not infer the caller's goal.

Exit codes: `0` means successful replay, `2` means invalid/unavailable proof or bad input, and `3`
means replay succeeded but `--require-proven` was requested for a non-PROVEN technical verdict.
A successfully verified DISPROVEN packet remains DISPROVEN. Operational acceptance and recovery
states remain separate from the historical technical verdict.

To detect rollback relative to a checkpoint already kept outside the deployment, add:

```powershell
python -I -m closure_engine.runtime.portable --bundle downloaded.json `
  --expected-trust-hash sha256:<operator-held-enrollment-digest> `
  --prior-checkpoint independently-retained-checkpoint.json
```

The output states whether that external prior checkpoint was checked. A trust pin authenticates
the enrolled signers; it does not by itself establish which signed head is newest. Keep checkpoints
in independent custody. This command does not claim that the local operator has configured a
remote WORM service, KMS or transparency log.

The aggregate portable container is bounded to 64 MiB, with at most 8,192 evidence objects and
1,024 history pages. Every signed protocol item and evidence object keeps the kernel's 1 MiB
bound. The container's JSON serialization is not a new signature canonicalization scheme:
existing signatures still use RFC 8785 canonical protocol bytes. Oversized exports fail explicitly
instead of returning a truncated proof. The legacy `evaluate-run` command also accepts this
expanded bundle, verifies its portable proof first and retains its existing external store/trust
arguments; old six-field run inputs remain supported.

## What the proof authenticates

The proof authenticates approved acceptance criteria, signed observations and receipts, retained
evidence bytes, ledger admission, deterministic interpretation and historical state. It permits
inspection of which expected value a primary observation was judged against. A cryptographic
signature does not establish that a verifier told the truth about physical reality or an HTTP
status. Another independent observer or authoritative-system read-back is still a distinct trust
source. Verification does not rewrite the original measurement or claim a current observation.

The deployed gateway is keyless and routes signing through separately scoped producer/custody
services. An operator token enrolled with several API roles deliberately permits that operator
to request several actions; process/key isolation does not establish human separation of duties.
Use separately enrolled API principals/role grants when the deployment requires separate human
approvers, actors or operators. Do not describe a multi-role administrative login as independent
human approval.

## Executed controls

`tests/test_runtime_portable.py` runs real persistent Ed25519 identities, a real deployed HTTP
target, observation windows and two accepted closures. The target is stopped before offline
checks. Tests cover authenticated download, pinned enrollment replacement, edited expectations,
policy/approval/signature/evidence alteration, missing evidence, dropped history, unsigned outer
input edits, duplicate JSON keys, aggregate exports larger than one protocol item, independent
checkpoint verification and rollback behind a real later signed checkpoint. No outcomes are
mocked; hostile cases modify only copies of recorded public proof.
