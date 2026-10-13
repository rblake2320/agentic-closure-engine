# Operate Agentic Closure Engine

ACE runs without an AI model or agent harness. It receives proposed work; the frozen contract,
authenticated observations and deterministic kernel decide its technical outcome.

## Enroll a target

`tools/start-product.ps1 -TargetProfile profile.json` installs the separate role services.
The profile is an operator input with `target_id`, `base_url` and `checks`. Each check has
`id`, `kind`, `phase`, `mandatory` and `probe`. Include a primary check, at least two protected
invariants, deployment, stage and baseline checks. Contract freezing enforces these minimum
acceptance requirements; profile enrollment alone does not establish an acceptable contract.
A minimal JSON publisher profile uses:

```json
{
  "target_id": "catalog",
  "base_url": "http://publisher:9002",
  "checks": [
    {"id":"version","kind":"primary","phase":"window","mandatory":true,"probe":{"type":"http-json","path":"/catalog","pointer":"/version"}},
    {"id":"access","kind":"invariant","phase":"window","mandatory":true,"probe":{"type":"http-unchanged","path":"/access"}},
    {"id":"retention","kind":"invariant","phase":"window","mandatory":true,"probe":{"type":"http-unchanged","path":"/retention"}},
    {"id":"deployment","kind":"deployment","phase":"instant","mandatory":true,"probe":{"type":"active-artifact"}},
    {"id":"stage","kind":"stage","phase":"instant","mandatory":true,"probe":{"type":"staged-artifact"}},
    {"id":"baseline","kind":"baseline","phase":"instant","mandatory":true,"probe":{"type":"baseline-custody"}}
  ]
}
```

Supply actual initial publisher content with `-PublisherArtifact initial.json`. Its format is
`{"routes":{"/catalog":{"version":1},"/access":{"publish":"broker"},"/retention":{"keep":"history"}}}`.
Choose your own content and criteria; the publisher is a real persistent HTTP service.

An external target implements GET `/ace/v1/state` (artifact_hash and generation), GET
`/ace/v1/artifact` (exact active bytes) and authenticated PUT `/ace/v1/artifact`. PUT receives
the exact bound bytes, an `If-Match` baseline digest and `X-ACE-Intent`; a changed precondition
must refuse the write. Configure the target with the broker credential's SHA-256 from the
bootstrap response. The raw deployment credential remains in the broker's private volume.
HTTP(S) probes stay on that enrolled origin; redirects and environment proxies are refused.

## Transactions and recovery

Open `http://127.0.0.1:8782/` with the operator token from `.runtime/operator.token`. Submit a
file or exact artifact text, an intent, and a JSON mapping from primary check IDs to required
values. These desired values are independent of the proposed artifact. Owner approval binds
both them and the pre-change restoration values into the evaluator digest.

Approve, freeze, record the independently read baseline, then execute and verify. The broker
writes its intent before the effect, checks the precondition, and reconciles by read-back.
The verifier samples the frozen observation window; evidence gaps do not become success.
The authority signs the result and custody independently replays it before admission.
The owner may separately accept PROVEN. A failed run can prepare a child recovery contract;
approve and execute that child, then complete recovery after it is PROVEN. The parent's
original technical verdict remains unchanged.

The JSON API is `/api/v1`; credentials are random-token digests and role gated. The shipped
`closure-engine api-credential` and `api-revoke` commands manage operator enrollment. The live
services reload credential directories. Mount the directory, not a single atomically replaced
file. Native `closure-engine init`, `enroll`, `target-enroll`, `tx`, `checkpoint`, `status`
and `reconcile` commands support operator-owned installations. Verification requires an
operator-held `--expected-trust-hash`; caller-selected clocks are not runtime inputs.

### Approval mode (separation of duties)

`api-serve --approval-mode single-operator` (default) keeps one credential free to hold every
role; `/api/v1/whoami` and the console disclose `single-operator-administration` for such a
credential, so approval by it is visible as not independent. `--approval-mode independent`
enforces separation: the gateway refuses to start if any credential holds both `actor`
(author) and `owner` (approver), reports `APPROVAL_SEPARATION_VIOLATED` naming the principal,
and on live reload a credential file that gains such a credential locks the API (every request
is 401) until the file is corrected. Proposals and recovery requests then carry the actor key,
approvals the owner key. Separation is enforced per principal name, not per token: the union of
roles across every credential enrolled for one principal must not span `actor` and `owner`, so an
alias (one person, two tokens) is refused like a mixed token. The authenticated proposing
principal is persisted with the transaction in custody at the receiving boundary (never taken
from a request body, never held only in gateway memory), and independent mode refuses an approval
by that same principal even after its actor token was revoked and it was re-enrolled as owner
(`403 APPROVAL_SEPARATION_REQUIRED`). Transactions proposed without a bound principal (CLI or
pre-0.4 history) are refused in independent mode (`409 AUTHOR_BINDING_MISSING`) rather than
assumed independent; the default mode records attribution and refuses nothing. `whoami` reports
`independent-approval`; `status` shows `proposed_by` and `approved_by`. This separates
credentials and principal names, not people: issue the actor and owner tokens to different humans
or systems, keep them in different custody, and do not enroll one person under two names.

## Cold backup and anchored restore

Stop/start preserves all volumes. Backup stops only this deployment, encrypts its state,
replays the written archive, records its digest and resumes the services:

```powershell
tools/backup-product.ps1 -OutputDirectory .backups/new-snapshot -KeyDirectory .backup-keys/new-key
```

Keep the decryption key in separate operator-controlled storage. Preserve an independently
held latest signed custodian checkpoint outside the archive; it is required for restoration.
A valid old archive cannot silently roll history back behind that anchor.
The wrapper saves `snapshot.receipt.json` beside the separate key, recording the archive digest
and trust pin before restart. `BACKUP_SAVED` means the archive exists; `Worked` is written only
after the services pass startup. A refused or failed restart terminates the wrapper with the
saved-state location. Keep the receipt apart from the archive. Directory separation is checked
through filesystem handles; choose independent storage if protection from device loss is needed.
For a restored deployment, pass its `-RuntimeDirectory`, `-DeploymentName`, `-ConsolePort` and
`-PublisherPort` to the backup command.

```powershell
tools/restore-product.ps1 -BackupDirectory .backups/new-snapshot `
  -KeyFile .backup-keys/new-key/snapshot.key -ExpectedArchiveHash YOUR_RETAINED_SHA256 `
  -TrustHash YOUR_ENROLLMENT_PIN -ExpectedCheckpointFile latest-checkpoint.json `
  -DeploymentName restored-authority
```

Restore targets new empty volumes. Incomplete installation has an INSTALLING marker and cannot
start; a retry with the same immutable archive checks existing bytes and resumes missing files.
COMPLETE is written last. There is no atomic rename across separate Docker volumes.
Staging uses tmpfs, so killed staging containers do not retain plaintext keys on a scratch disk.
The restore container checks the supplied archive digest against a private frozen copy before
decryption. Configuration export uses a source-bound sibling staging directory; a failed copy
can resume with the same archive and checkpoint, and promotion refuses an existing destination.
The plain `.restore-source.json` records operator-selected inputs; it is not a signature.
Startup refuses another active deployment with the same signing enrollment. Stop the original
authority before activating restored keys; never operate two independent ledgers with them.
Use `tools/start-product.ps1` for every start; direct Compose invocation bypasses the host
single-authority check. Do not configure another restored authority to start automatically.

## Independent replay and AWL

Authenticated viewers can fetch signed closure envelopes, audit-export pages and evidence by
digest. Consumers rebuild a fresh verifier ledger, check exact and prior checkpoints, and
reconstruct technical packets with public keys only. AWL's optional pairing installs that
verifier library and mounts only a viewer credential, public enrollment and an external anchor.
It receives no signing or deployment credentials and cannot change ACE verdicts.

Retain signed JSON as raw response bytes. Some clients coerce timestamp strings during JSON
round-trips, changing the signed content. A changed signature or packet digest must be refused.
