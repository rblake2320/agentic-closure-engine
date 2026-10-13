# Physical validation and authenticated replay prefixes

The runtime can reuse a previously reconstructed ledger context within one process.
This changes the warm replay architecture: old transitions are not applied again when
their physical inputs are byte-identical. New transitions still run the native `_apply`
rules. The cache does not accept a signed checkpoint as a substitute for reconstruction.

## Admission and invalidation

A prefix is initially created only after successful native full-history replay. It
contains the derived states, admitted packets, run bindings, chronology and prior
evidence-obligation sets. A subsequent validated suffix can extend that context.
It is serialized into immutable process-local bytes; every caller receives a fresh
copy. Each Ledger instance has its own ownership identifier. Nothing is persisted.

Before every reuse the runtime:

1. Physically reads all ordered SQL event rows and SHA-256 hashes their actual
   envelopes, comparing sequence, event ID, actual digest and stored digest with the
   reconstructed prefix. Deleted, reordered, truncated or edited rows invalidate it.
2. Physically reads and hashes every registered contract and approval. Previously
   registered pairs must match. New contracts are authenticated before suffix replay.
3. Physically opens and SHA-verifies every evidence object transitively consumed by
   the previous replay, including input manifests, baseline/protected resources,
   evaluator bundles and observation evidence. The dependency set comes from actual
   successful `EvidenceStore.get` calls, including nested packet replay; arbitrary
   strings in opaque payloads are not treated as asserted dependency manifests.
4. Verifies the external checkpoint against freshly checked chain membership, then
   applies each new signed event with the prior chronology, event IDs, contract links
   and evidence-obligation sets. A terminal packet cannot omit an earlier admitted FAIL.

An incompatible fingerprint or failed evidence read discards the prefix and invokes
native full replay, which classifies or refuses the current physical history. A failed
replay or any failed semantic read is not retained as a new context. No file mtime,
size, caller-supplied head, database digest column or signed snapshot alone authorizes
reuse. Enrollment and protected source-code epochs are included in the key; frozen
policy and evaluator bindings remain within the exact retained contract bytes.

## Audits, restart and limits

Constructor/reopen, `verify`, CLI `summary` verification and `audit_export` apply the
full historical transition sequence. Independent scoped/offline replay remains native
and cannot receive a cached seed. Successful fixed-byte authentication and deterministic
packet-reconstruction memoization still require fresh physical custody checks.

Restart begins without semantic context. Killing an owned verifier process after prefix
validation but before an append does not persist a new transition or cache. External
checkpoints continue to detect rollback/truncation. The operating-system custody and
protected evaluator/key boundaries remain necessary; process memory is trusted runtime
memory, not an actor-writable status file.

All retained authentication, packet replay and prefix pools share one LRU limit:
8,192 entries and 64 MiB, including serialized context, dependency fingerprints and
bookkeeping. Eviction falls back to reconstruction. Legacy offline evaluator references
that are not physically held in custody retain their original cold semantics and cannot
create a prefix after a failed evaluator read. Runtime evaluator bundles are retained.

Runtime custody unconditionally enables a private Ledger policy requiring physical
evaluator custody for every registered frozen contract, including cold reads and
pre-baseline approval. There is no request or actor CLI switch to disable it. The
legacy offline kernel policy remains unchanged. An executed cold-runtime regression
found the distinction necessary: a changed evaluator could otherwise survive cold
legacy replay even though the warm replay cache refused it. Both changed and deleted
runtime bundles are now required to fail warm/cold checks; restoring bytes works.

Custody status and technical-packet reads delegate to this validated Ledger snapshot
under the custody lock. The older `(mtime, size, inode)` snapshot shortcut was removed:
executed live PROVEN controls showed that same-metadata changes to ledger bytes, raw
evidence, inputs or evaluators otherwise returned stale success, and a returned mutable
dictionary could poison later status. Exact original-byte restoration is the green control.

## Repeated-release control

`tools/profile_history.py` performs real installed-runtime deployment and target read-back
over loopback HTTP, with six generated signing identities and custody RPC. It registers
a 3,000 ms window, three required samples, five issued challenges, a 1,500 ms maximum gap,
1,000 ms clock skew and 2,500 ms settle time. These criteria were unchanged throughout.
The candidate continues an exact copy of the original twelve-transaction failed history.

Retained unsuccessful predecessors are deliberately not replaced:

| Implementation | Continuation before next INDETERMINATE | Total retained transactions at failure |
|---|---:|---:|
| Released 0.3.1 | First fresh-process continuation fails | 13 |
| Successful packet result cache | 12 PROVEN, next fails | 25 |
| Fixed-byte event/contract authentication cache | 18 PROVEN, next fails | 31 |
| Binding/receipt and per-replay parse refinement | 23 PROVEN, next fails | 36 |
| Prefix with strict evaluator and fresh high-water anchor | 33 PROVEN, next fails | 46 |
| Complete bounded reads and once-per-invocation contract parsing | 64 PROVEN; no failure | 76 |

The original live run had ten PROVEN releases then two INDETERMINATE releases; first
protected samples arrived after the unchanged 1,000 ms leading coverage bound although
all five admitted raw samples were PASS. Pure replay profiles confirmed increasing
historical transition reconstruction cost. The three partial improvements did not close
the registered 64-release gate. The authenticated-prefix and repaired custody results are
recorded separately in their installed control receipts. This finite control does not establish
an unbounded rate or 2,880 releases/day.

At source `6c8bf6b`, installed preview wheel SHA-256
`56000c8e703ce74f84ca0dc708c8de0e3c65ff3bce47161602167701cfbe4930`
completed all 64 registered releases, followed by one successful release from a new
process against the unchanged retained history (77 transactions, 693 events). The
64-cycle median was 7.340 seconds, range 6.500–10.781 seconds; the largest first protected
sample offset was 163 ms, within the unchanged 1,000 ms bound. Five samples per invariant
were issued and received for every release; the contract required three.

The last measured warm snapshot at 76 transactions took 96 ms while performing 535
physical get/SHA validations. The earlier anchor-enforced 46-transaction failure measured
537 ms with 325 reads; its first samples were 1,187/1,336 ms. The complete reader now
uses a 4 KiB first chunk and bounded subsequent chunks instead of allocating MAX+1 for
every tiny object. It still reads and hashes all admitted bytes. Actual files at zero,
4 KiB, 64 KiB and 1 MiB boundaries, truncated files and oversized files are tested.
Authenticated contract bytes are decoded into one fresh invocation-local dictionary;
their physical reads, digests and exact approval authentication remain mandatory.

`tools/verify_history_integrity.py` exercised the resulting 77-transaction public-only
clone: all nine row/approval/evidence/evaluator/baseline/rollback mutations refused both
warm and cold with matching typed reasons; all nine exact-byte restoration controls
worked. Native full audit agreed with warm context. Its retained cache used 1,233 entries
and 4,234,046 bytes across the shared pools. Original failed histories and intermediate
candidate receipts remain in the private `evidence-runs` directory.

Custody also authenticates its configured checkpoint file before reads and appends,
retains an immutable in-memory high-water checkpoint, and advances the Ledger anchor
after successful persistence. An independently executed real signed history promotion
from checkpoint 9 to 18 works; truncation behind 18, missing files and authentic older
files refuse while warm. A new process with an intact later history and an authentic
older checkpoint cannot infer a previously unseen external commitment: independently
retained latest checkpoints/witnesses remain the cold rollback boundary. A real process
kill after SQLite append but before checkpoint publication remains reconcilable against
the prior anchor. Exact old-event retries preserve their event hash and return the current
global head/sequence without lowering the checkpoint.

`tests/test_history_performance.py` exercises real files, database mutation, signing keys,
cached valid/malicious suffixes, trust swaps and an owned-process kill. Its previous test
requiring every old `_apply` on every warm read was replaced deliberately: the approved
architecture reuses authenticated context after physical validation. The replacement
asserts semantic equality, mandatory-failure retention, historical mutation refusal and
full `_apply` traversal during an explicit audit.
