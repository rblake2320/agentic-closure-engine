# Public historical time assurance (0.4 candidate)

`ace.time-assurance.v1` is a separate, public-only wrapper around an unchanged
`ace.portable.v2` bundle. It contains the bundle and retained signed time sidecars. It does
not alter historical contracts, closure packets, ledger events, verdicts or the portable
v2 format. Existing `bundle` routes/commands keep their existing behavior.

An authenticated global viewer can request:

```text
GET /api/v1/transactions/<transaction-id>/time-assurance
```

Local and distributed runtimes provide `time_assurance(transaction_id)`. Custody has the
read-only `witness_record(event_hash)` library/RPC seam. A missing/unwitnessed historical
subject produces `TIME_ASSURANCE_UNAVAILABLE`; its technical `PROVEN` or other verdict is
preserved. The software never fabricates a retrospective independent timestamp.

## Independent offline verification

Copy only the public wrapper file to the verifier, then run:

```powershell
python -I -m closure_engine.time_assurance --proof public-time-proof.json `
  --expected-authority-hash sha256:<independently retained ACE trust pin> `
  --expected-witness-hash sha256:<independently retained witness manifest pin> `
  --expected-transaction accepted-change `
  --expected-contract-hash sha256:<independently expected frozen contract> `
  --expected-artifact-hash sha256:<independently expected artifact>
```

All five expected bindings are mandatory. A public key or pin included in the wrapper
does not enroll itself. The verifier holds no signing key, receives no client credential,
contacts no live target/witness/custody service, and first runs the existing public-only
portable verifier. Optional `--prior-checkpoint` supplies an independently retained native
ledger prefix to detect rollback; pins alone do not prove the latest historical head.

The API and wrapper have the same global-viewer audience as the existing custody audit.
This is not a new tenant-isolation boundary. Raw evidence retains portable v2's requested
transaction/recovery scope. Foreign signed global metadata remains in the native chain;
foreign temporal sidecars and private artifact/evidence bodies are not added by this wrapper.
Bearer values, signing keys, token paths and CA/private file references are not exported.

## What is required and checked

The required event set is derived from authenticated history, never unsigned wrapper labels:

- The exact authority terminal event that admitted the selected technical verdict.
- Its cryptographically linked parent failure events for a recovery child.
- The selected owner acceptance event when the native state is `ACCEPTED`.
- The final `RECOVERED`/`RECOVERY_FAILED` authority event when that is the selected state,
  and the exact child's admitted terminal event if a child packet is supplied.

The sidecar set must match exactly. Missing, duplicate, unrelated, altered or substituted
records are refused. Every native event must belong to the already verified native chain.
The verifier checks the independent witness manifest pin, enrolled authority pin, witness
signature, exact subject/purpose/digest/nonce, custodian-signed consumption proof, expected
head/config/event bindings, unique nonce/witness sequence/consumption index and their
chronological ordering. These records are a selected subset; this does not assert that the
wrapper includes the complete global witness or consumption log.

Acceptance's subject must be the technical packet already admitted for that transaction,
not a candidate packet from the caller. Recovery timing uses frozen child owner approval,
immutable retained parent deadline and the native `recovery_status` evaluator at signed
witness reception time. A future child evaluation cannot be treated as observed. All
native signatures, evidence/contract bindings, input completeness and invariants still run
through portable v2 replay. No AI or second verdict evaluator is introduced.

Freshness is historical: the receipt must have been temporally admissible when received and
consumed under its pinned policy. It is not newly stamped or rejected merely because the
offline verifier runs later. Custodian consumption time is a signed custodian assertion;
the independent witness's reception time remains the separate observation. A compromised
custodian signing key can forge consumption assertions, and a compromised witness clock or
signing key can lie. External administration and independently retained pins/checkpoints are
part of the declared trust boundary.

## Meaning of the result

The response separates `technical` (the unchanged replayed verdict and native state) from
`time_assurance.status = HISTORICAL_WITNESSED`. Its scope is terminal/acceptance/recovery
events selected above. It does not claim every actor/owner/broker/verifier date was witnessed.
It does not claim current target state, subsequent drift protection, absolute/hardware UTC,
or independent human approval. The clock claim is the enrolled witness host's system UTC.

AWL's existing CIP path is not silently upgraded to require this wrapper. A receiving AWL
policy must explicitly configure/verify independent time assurance before projecting that
stronger level. Merely installing either product does not make old CIP receipts time-qualified.

## Executed proof controls

`tests/test_time_assurance.py` runs a genuine target change, independently keyed TLS witness
in a separate process, actual owner acceptance, authenticated API/RPC download and a fresh
offline process after both live services have stopped. It includes two independently supplied
pins and subject bindings, signature/manifest/config/subject tampering, missing/duplicate/
foreign receipts, the parent-child-recovery event set, and unchanged native truth when time
proof is unavailable. The test witness has a frozen five-second receipt-age policy: the
original receipts are already expired at verification time, making historical freshness
an exercised property rather than a prose claim.
