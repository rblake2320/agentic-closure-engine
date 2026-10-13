# Portable closure proofs

The minimum verifier for `ace.portable.v2` and the repaired runtime's extended diagnostic
action receipts is **Agentic Closure Engine 0.3.1**. Use the release wheel and independently
retained SHA256, not an older interpreter merely because it imports `closure_engine`.
The released 0.3.0 verifier cannot interpret these new receipt fields and may recompute
such a run as INDETERMINATE with SCHEMA_INVALID. That is a version incompatibility, not
evidence that the admitted 0.3.1 result was false. Never substitute that older result for
the authority's verdict or claim that the 0.3.0 binary supports the repaired format.
The 0.3.1 runtime/verifier retains old signed ledger records and historical safe slash IDs
unchanged; actual old/new installed HTTP migration is covered by the release gate.
Every downloaded v2 proof also carries the minimum-version notice in `portable.scope`.
The verifier checks that notice against its required profile, rather than relying only
on a separate web page that the recipient might not have received.

The authenticated `GET /api/v1/transactions/{id}/bundle` download includes the frozen contract,
owner approval, run binding, observation/ingestion records and deployment receipts. Its
`portable` member adds the public enrollment, owner-approved evaluator definitions (including
expected and restoration values), known kernel policy version identifiers, complete signed
global signed event envelopes, signed custodian checkpoint and exact content-addressed evidence
bytes for the requested transaction and its required recovery relationships. Unrelated
transactions' artifacts, observation bytes and top-level contract/evaluator catalogs are excluded.
The custody audit-export response also supplies the public enrollment; it contains public
Ed25519 keys and role assignments, never private signing keys or bearer credentials.

The complete global signed event chain is necessary because a transaction's events are linked
through intervening events for other transactions. Those envelopes expose shared ledger metadata
(including identifiers, event/packet bindings, hashes and any embedded recovery-contract fields).
This is transaction artifact
minimization, not tenant isolation or concealment of all foreign metadata. API viewer grants are
global; deployments needing tenant access controls must not describe them as tenant-scoped.
Raw artifact or probe JSON is treated as opaque bytes: a hash-looking string inside it never
authorizes following another custody object. This export explicitly refuses a concurrently
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
signature; applies the shared ledger chain checker to all event metadata and the existing
`Ledger._apply` transition/evidence rules to the declared transaction scope; and uses the existing
`replay_packet`/deterministic verdict evaluator. It additionally checks that the readable
evaluator expectations and legacy run inputs exactly match their authenticated retained inputs.
There is no new verdict algorithm or AI judge.

The format is `ace.portable.v2`. Its signed chain authentication and semantic evaluation scope
are distinct. Verification returns `verification_scope`, with the requested transaction and
required recovery ancestors/children, and `foreign_transaction_semantics: NOT_EVALUATED`.
Only scoped transaction states appear in the verified result. Prior OBSERVING packets are still
fully replayed: a terminal packet omitting a previously ledgered qualified FAIL is rejected by
the unchanged `LEDGERED_EVIDENCE_OMITTED` rule. The older v1 verifier refuses v2's version/fields;
it must not silently claim full global replay. Use the updated installed verifier.

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

`tests/test_runtime_portable_scoped.py` additionally deploys two real targets with distinct
private artifact canaries, verifies accepted closures after stopping both targets, and checks
that A's bundle excludes B's bytes even when A's own artifact contains B's artifact digest.
A real failed change and successful recovery retain required parent/child evidence without
exporting B's bytes. A separately labelled cryptographic adversarial probe constructs a genuinely
signed false PROVEN packet that omits a previously ledgered mandatory FAIL; scoped replay refuses
it while its truthful DISPROVEN control succeeds. Foreign event signature tampering, dropping
an own event and changing the scope/version are refused.
