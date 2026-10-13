# Required reception witnessing in custody (0.4 candidate)

Custody can enforce reception witnessing before **new authority-signed events** (including
`RECOVERY_FAILED`) and before owner `ACCEPTED` events. It requires an operator profile, not
a caller-selected request option. The default without a profile remains the existing mode.
Installing a witness service does not itself turn this enforcement on.

Create `<operator-role-root>/witness-gate.json` as trusted deployment configuration:

```json
{
  "version": "v1",
  "endpoint": "https://independent-witness.example:8790",
  "manifest": {"...": "exact independently enrolled public witness manifest"},
  "expected_witness_hash": "sha256:<independently retained witness manifest digest>",
  "expected_authority_hash": "sha256:<existing independently enrolled ACE trust pin>",
  "token_file": "/private/witness-client.token",
  "ca_file": "/public/operator-witness-ca.pem",
  "timeout_ms": 10000
}
```

The manifest placeholder above denotes the complete public JSON produced by witness
enrollment, **not** a literal valid configuration. Its `subject_purposes` must grant
`closure-packet` and `ledger-event`. File references must be absolute paths visible to custody.
On Windows use absolute Windows paths and JSON escaping. The client credential belongs in a
private read-only mount; never put its value in the profile. The CA is public. Custody requires
HTTPS, hostname verification, TLS 1.2 or later, an explicitly trusted CA, no environment
proxy and no redirects. Python 3.13 requires properly issued CA identifiers; certificate
verification is never relaxed to compensate for an invalid CA.

The profile is frozen to a digest in a custodian-signed `custodian/witness/required.json`.
Required mode latches **before the first profile is parsed**, so a malformed first enrollment
followed by profile deletion cannot silently revert to normal mode. An initially valid
profile freezes immediately. A failed first enrollment can be corrected to a valid profile,
then that profile is frozen. After freezing, changing/removing/unreading the profile or its
private references fails closed. This release does not expose an in-band policy downgrade
or key-rotation command. Administrative recovery of protected configuration is outside actor
authority; never delete the required marker to make an unavailable witness look successful.

Startup checks sticky configuration. Every new guarded append reloads it and checks again
after network preparation. An unavailable witness prevents the guarded append. Read-only
historical technical verdicts remain valid and are not rewritten. Unguarded actor/owner/broker
steps retain native role/state verification; they do not implicitly acquire witnessed assurance.

## Exact subject and operation binding

Authority events request a receipt over the exact signed event's canonical digest and signed
`ledger-event` purpose. Acceptance requests a `closure-packet` receipt over the authoritative
`PROVEN` packet already admitted to the ledger for that transaction; it never uses a caller's
supplied candidate. Native ledger role/state checks remain decisive after witnessing. A
receipt is **not** permission to append a logically invalid transition or incomplete verdict.

For every `RECOVERY_FAILED`, the gate reuses native `recovery_status` with the signed
witness reception instant, the immutable parent contract's retained recovery deadline,
and the frozen child contract/owner approval when a child packet is supplied.
It refuses `WITNESS_GATE_RECOVERY_DEADLINE_NOT_OBSERVED` while that independent receipt
clock says the deadline has not elapsed, even if the signer's timestamp leads by the
permitted two-second skew. A pre-deadline receipt cannot become an after-deadline proof
merely by waiting before consumption. New after-deadline reception is required.
Immediate independently observed restoration failure remains failure before the deadline;
an unverified child whose deadline has not elapsed remains recovery-required.

Custody writes `witness/pending.json` before calling the witness, binding the exact signed
event, event digest, expected ledger head, subject, subject purpose, policy digest and fresh
256-bit nonce. A different operation cannot reuse an active pending slot. Wrong head or
conflicting event is rejected before an external witness call. A signed receipt for another
subject or a mutated pending subject cannot authorize the original event.

The received receipt is persisted before consumption. A privileged SQLite journal then
atomically commits a custodian-signed consumption proof and its unique nonce/sequence cursor.
The proof binds event, subject, receipt, nonce, witness sequence, expected head, config digest,
consumption index and previous proof digest. A fabricated unsigned row or changed proof is
refused. The normal witness verification code checks signature, independent pins, subject,
purpose and freshness; no second verdict evaluator is introduced.

## Interrupted operation reconciliation

`runtime.witness_gate.reconcile_witness_operation(custody)` resumes **only** the stored exact
signed operation. It does not mint a new event/time/nonce, consume another receipt or blind
retry a deployment. After consumption but before append, it requires the exact valid signed
consumption record. After append but before completion, it recognizes the exact event in
verified history and lets native idempotency rebuild the custody projection/checkpoint.
Packet references are deduplicated, preserving their original order and packet bytes.

Once a receipt was validly consumed, a later restart reconciles that historical consumption;
it does not claim the receipt was freshly obtained at restart. If the receipt had not been
consumed before its freshness bound elapsed, fresh verification refuses it. An old `PROVEN`
packet cannot acquire a new acceptance receipt by silently restamping its evaluation time.
Terminal technical truth remains unchanged while operational acceptance is withheld.

The signed consumption proof and replay cursor share one SQLite transaction (`BEGIN IMMEDIATE`,
DELETE journaling, `synchronous=FULL`). Guarded operations use a cross-process OS file lock,
released by the OS when a process dies. Existing exact historical event retries without any
witness record remain native idempotent retries; they do not gain retrospective time assurance.

## Retained public records and trust limits

`runtime.witness_gate.witness_record(custody, event_hash)` retrieves a read-only public sidecar
under `custodian/witness/receipts/<event-digest>.json`, verifies the custodian consumption
signature, witness signature/manifest, subject binding and actual native ledger membership.
It contains signed public material, not bearer credentials or private signing keys. Sidecars
are created before admission but retrieval refuses records whose event was not admitted.

This library seam is available for portable proof integration. Merely retrieving/including
a sidecar does not establish that an external recipient independently checked its expected
witness pin or the operator's required-time policy. A receipt supplied by the actor cannot
enroll its own witness. Root's receiving policy and public proof/export integration remains
a separate gate.

The journal assumes custodian keys and its protected state directory are outside actor
control. A compromised custodian signing key can produce false consumption proofs. Signed
rows do not provide a WORM guarantee against deleting all authentic suffix state; separately
retained external checkpoints remain necessary for privileged rollback assurance. The witness
signer observes reception using its own system UTC. A separate signature on the same host is
not independent truthful time. Use a separately administered host/clock and retain pins outside
both actor and witness custody. This does not claim GNSS/hardware time or an RFC 3161 TSA.

## Executed controls

`tests/test_witness_gate.py` uses a real trusted TLS witness, real persistent identities, real
disposable target deployment/read-back, and subprocess kills at deterministic fault boundaries.
The injector pauses **after real journal commit** or **after real admitted PROVEN**, then kills
the process; it does not mock a successful effect. Controls cover normal unconfigured mode,
PROVEN and acceptance, required profile deletion/first-malformed enrollment, unavailable
witness, signed future `RECOVERY_FAILED`, exact crash reconciliation, unique packet refs,
wrong subject, pending mutation, different event conflict and a forged journal entry.
