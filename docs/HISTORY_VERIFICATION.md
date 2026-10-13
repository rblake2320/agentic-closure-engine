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

The original live run had ten PROVEN releases then two INDETERMINATE releases; first
protected samples arrived after the unchanged 1,000 ms leading coverage bound although
all five admitted raw samples were PASS. Pure replay profiles confirmed increasing
historical transition reconstruction cost. The three partial improvements did not close
the registered 64-release gate. The authenticated-prefix result is recorded in the
installed control receipt after that run completes. This finite control does not establish
an unbounded rate or 2,880 releases/day.

`tests/test_history_performance.py` exercises real files, database mutation, signing keys,
cached valid/malicious suffixes, trust swaps and an owned-process kill. Its previous test
requiring every old `_apply` on every warm read was replaced deliberately: the approved
architecture reuses authenticated context after physical validation. The replacement
asserts semantic equality, mandatory-failure retention, historical mutation refusal and
full `_apply` traversal during an explicit audit.
