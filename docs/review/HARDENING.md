# Review-driven hardening, 2026-10-11

Input source inspection was pinned to commit 7795b601eb18828f6b0906f734c7cea4b07de9a9;
the retained manifest hashes each tracked Git blob. The owner-supplied review was not treated
as a fresh test execution. Phase 0's historical validation remains a separate result.

F01 reproduced: an enrolled authority could sign fabricated PASS checks and PROVEN over
an empty evidence set; the old ledger accepted it. Regression:
test_signed_fabricated_success_must_be_replayed. Red JUnit is retained locally. Packet issuance
now retains an immutable input manifest and signs inputs_hash. A public-key-only replay
function reconstructs the entire body. Terminal admission, observation admission and recovery
packet admission invoke this replay. The CLI exposes verify-packet. Valid controls run beside
fabrication, reason/check/admitted/rejected/window discrepancies. The ledger remains conservative
with full replay on append, including retained input reads. This increases F05's audit cost.

Protocol compatibility: package 0.2.0 requires inputs_hash and a new policy digest. Previously
frozen 0.1.0 contracts/ledgers are preserved with their original pinned verifier; they are not
silently migrated or accepted under the new policy. New approvals must bind the new policy.
Envelope family names remain v1; the stronger policy is explicitly digest-bound.

F06 is a test-only external Haiku worktree; root reviews and independently runs its contribution.
Non-admissible observations never become failures merely because they contain the word FAIL.

Remaining production review work is separately tracked: F02 operator-authenticated enrollment,
rotation/revocation; F03 hostile filesystem custody and no-follow guarantees; F04 explicit
protected-resource restoration coverage and external current-state read-back; F05 bounded
authenticated snapshots/segment roots. No operating identity, ACL or production key changes
are bundled into this offline release. AWL is a separate repository/product, using ACE replay
through an optional adapter rather than copying verdict logic.
