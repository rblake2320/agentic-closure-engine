# Separately enrolled closure reception witness

The witness observes **receipt of authenticated closure packet canonical bytes** and signs their digest,
authority trust digest, subject, evaluation timestamp, reception timestamp, fresh client nonce,
sequence and previous receipt digest. It does not evaluate the technical verdict. A late or
unavailable witness does not rewrite a historical `PROVEN`; it prevents a consumer configured
to require a fresh witnessed reception from proceeding with a new operational acceptance.

The shipped module runs without an AI harness:

```powershell
python -m closure_engine.time_witness init --root witness-state --issuer witness-site-b `
  --authority-trust operator-authority-trust.json --expected-authority-hash sha256:<operator-pin>
python -m closure_engine.time_witness serve --root witness-state `
  --expected-witness-hash sha256:<operator-witness-pin> --expected-authority-hash sha256:<operator-pin>
```

Enrollment outputs the **public** manifest and its digest, and the path of a locally created
private client credential. It does not print the credential or signing key. Copy the public
manifest and retain its digest through a channel independent of the receipt server. The ACE
authority trust digest is a separate independently supplied pin: a packet, server or manifest
cannot enroll its own authority. The witness issuer and key must differ from every enrolled
ACE identity. `signer/identity.key` remains private to the witness operator. POSIX creation
uses mode `0600`; Windows deployments must supply the same protected-account/key-volume
boundary as other ACE role services. File modes do not establish distinct Windows principals.

Generate a fresh 256-bit hex nonce in the consumer and retain it with its pending request.
Do not copy a nonce from an unsolicited receipt. The actor must not write the consumer journal.

```powershell
python -m closure_engine.time_witness request --url http://127.0.0.1:8790 `
  --token-file witness-state/client.token --packet closure.json --nonce <64-hex-digits> --out receipt.json
python -m closure_engine.time_witness journal-init --journal consumer.sqlite
python -m closure_engine.time_witness verify --receipt receipt.json --packet closure.json `
  --manifest independently-enrolled-manifest.json --expected-witness-hash sha256:<operator-witness-pin> `
  --authority-trust operator-authority-trust.json --expected-authority-hash sha256:<operator-pin> `
  --nonce <same-pending-nonce> --journal consumer.sqlite
```

The receiving authority must run verification/consumption and require exit `0` / `WITNESSED`
before its own acceptance operation. These are explicit sidecar commands; installing the
module alone does **not** change the existing ACE ledger's acceptance policy. The module
does not modify old contracts, signed packets or ledger events. Integrations may call
`ConsumerJournal.consume` with the same pins and nonce instead of spawning the CLI.

New enrollment also permits authenticated `ledger-event` subjects signed by the enrolled
**authority**, only in native ledger states authorizing that role (including `RECOVERY_FAILED`).
Actor-, owner- or other-role events cannot obtain this authority-event receipt. Pass the
signed event through `request --packet event.json`; verify it with
`verify --subject-purpose ledger-event --packet event.json`, or pass
`expected_subject_purpose="ledger-event"` to the library consumer. Receipt `subject_purpose`
is signed and consumers require exact purpose agreement. The default is `closure-packet`:
an event receipt cannot be silently accepted as a closure receipt.

For events, the witness bounds signed `created_at` against its own clock and checks any
attached closure packet's timestamps. It does **not** decide whether the state transition
or recovery deadline is correct; native ledger replay remains necessary. Custody must
verify/consume an event receipt **before appending** when its policy requires witnessed
event time. Installing this module does not enforce that integration. Its future tolerance
is a declared clock-skew allowance, not exact UTC equality. Legacy closure-only witness
manifests/receipts remain readable unchanged; a legacy manifest does not grant event
witnessing. Broader enrollment requires a new independently retained pin.

The CLI `verify` always consumes the receipt into a durable journal. `verify_receipt` is a
read-only library primitive; repeated read-only verification is intentionally permitted and
is not anti-replay consumption. Exact same-nonce/same-packet retries at the witness return the
original receipt without a new time or sequence. Different packets under the same nonce are
refused. Consumers refuse already consumed or older sequences after restart. Consumers may
observe only a subset of the shared witness log, so gaps in their sequence are permitted;
they are not presented as a verified full chain.

## Clock and custody trust model

The witness reads its **host system UTC**; requests contain no `now` or reception time. Default
policy permits packets no older than 60 seconds, receipts no older than 60 seconds, a 2-second
future tolerance and a 2-second deviation between UTC elapsed time and process-monotonic elapsed
time. Custom initialization policy is available through the library and frozen in the independently
pinned manifest. Receipt issuance checks packet evaluation, envelope creation and window-end
timestamps against reception. It refuses wall-clock regression behind committed reception time,
including across service restart, and detects clock steps while the process is running. Equal
UTC milliseconds are allowed; sequence is strictly increasing.

This is an **independent signer observation, not independent truthful UTC**. Running the witness,
authority and consumer on one host does not create an independent clock. A shared clock moved
before all processes start can fool all three; the automated limitation control explicitly
demonstrates this. Forward jumps across witness restart cannot be diagnosed from signatures or
monotonic time alone. For independent clock assurance, operate the witness on a separately
administered host with an appropriately managed clock, or add a separately trusted timestamp
authority. No RFC 3161 TSA, GNSS clock, hardware time root or paid service is implied here.

The witness trusts an enrolled ACE authority to sign closure packets; it checks that signature
and the timestamp bindings, but does not reconstruct the underlying evidence or declare a
closure verdict. Use ACE portable proof replay in addition to this reception witness. A
compromised witness signer can sign false observations. Independent pinned identities,
operating accounts and protected key/storage boundaries remain operator responsibilities.

## Persistence, external checkpoint and transport

Receipt appends use SQLite `BEGIN IMMEDIATE`, DELETE journaling and `synchronous=FULL`. Each
request first replays all signed receipts, row sequences, previous hashes, nonces and UTC
monotonic ordering. Missing DB state is refused rather than recreated. Killing after commit
but before receiving a response is safe to retry using the original nonce.

```powershell
python -m closure_engine.time_witness checkpoint --root witness-state `
  --expected-witness-hash sha256:<operator-witness-pin> --expected-authority-hash sha256:<operator-pin>
```

Retain that JSON outside witness storage. On subsequent `serve` or `checkpoint`, supply
`--expected-checkpoint independently-held-checkpoint.json`. The service refuses history
truncated/rolled back behind that exact signed-receipt prefix. Signed rows alone cannot
detect deletion of an authentic suffix or replacement with an older authentic database:
the independently retained prefix is essential. A locally generated checkpoint is not an
external anchor until another custodian actually holds it. The local consumer journal is
also privileged state, not an actor-editable cache.

Default HTTP binding is loopback. Non-loopback bindings require `--tls-cert`, `--tls-key`,
and explicit `--allowed-host hostname:port`; remote clients require HTTPS and system-trusted
certificate verification. Never disable certificate verification. Credentials travel only
to the configured origin: the shared service client refuses redirects and ignores environment
proxies. Host/Origin and duplicate credential/body header checks reuse ACE service plumbing.
Only authenticated `POST /receipts` and `GET /checkpoint` are supported.

## Executable controls

`tests/test_time_witness.py` deploys a real disposable HTTP target with real persistent ACE
role identities, obtains a genuine `PROVEN` packet, and runs the witness in a separate process.
It kills/restarts the service and tests exact retries plus fresh sequences. A real admitted
`PROVEN` ledger event is witnessed without changing its original canonical bytes. Separate
signer-adversary tests submit signed, deliberately future-dated `RECOVERY_FAILED` events;
these are primitive probes, not admitted real recovery transitions. Other controls
cover distinct enrollment, substituted pins/keys/packets, invented authority, signed nonce
replay, late/future packet times, receipt age, equal/regressing/stepped clocks, altered history,
externally checkpointed truncation, missing DB, concurrent retry and refusal of remote HTTP.
Only the explicitly named clock-fault controls override clock reads; no outcomes or signatures
are mocked. This gate is local separate-process evidence, not an executed second-host or
hardware-clock deployment.
