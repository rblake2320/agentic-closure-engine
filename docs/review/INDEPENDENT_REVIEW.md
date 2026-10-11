# Independent review and disposition, 2026-10-11

Opus5.5 reviewed pinned ACE ce35789 and AWL c88a440 in isolated worktrees, with private
installed environments. Haiku5.5 supplied conflict and actual HTTP authorization tests.
Neither helper edited canonical code or shared trackers. Root owns repairs and release gates.

| Finding | Observed red case | Enforced disposition |
| --- | --- | --- |
| O-01 | Terminal packet omitted a qualified FAIL from an earlier ledgered input set | Packet inputs must retain every earlier ledgered record/receipt; replay checks continuity |
| O-02 | AWL accepted a late PROVEN packet refused by ACE's already-final ledger | Adapter requires operator-configured Ledger and exact technical_packet equality |
| O-03 | Replacing trust enrollment could substitute a coherent world | Verification CLI requires independent expected-trust-hash before opening custody |
| O-04 | Recovery changed window invariants to instant checks under identical IDs | Parent invariant definitions/evaluator retained; window parameters cannot weaken |
| O-05 | Reporter self-accepted HUMAN work | Core refuses self-acceptance; HTTP operator authority derives from enrolled credential |
| O-06 | Forged assurance survived unsigned operational audit | Packet retained/replayed; missing adapter yields explicit unavailable, audit exit3/API503 and dependency claim denial |
| O-09 P1/P2 | Event/evaluation timestamps regressed | Non-decreasing event and transaction evaluation time enforced in append and replay |
| O-10 | Receipt preceded run binding beyond clock skew | Pre-binding receipt rejected; exact boundary control passes; OBSERVING binding also checked |

Root reproduced red controls before repairs. Source-only issues are not called executed
failures. Opus independently reran ACE137 tests at7646dcc and AWL78 at6ee2410, and checked
that adopted probes were not weakened. The final chronology controls are additional to
those snapshots. Haiku independently reran43 real HTTP checks, including framing/timeouts.
Final machine receipts supersede these intermediate counts.

The O-06 follow-up mattered: merely retaining a fake packet dictionary was insufficient.
The stronger regression requires that the dependent task cannot be leased while its
prerequisite's independent assurance is unavailable or invalid. Audit is explicit rather
than converting absent verification into success.

Executed residual O-09 P3: a key holder asserting a future event date can classify missing
restoration as RECOVERY_FAILED. This did not produce false PROVEN. Event time is a trusted
operator/authority assertion in the offline protocol; monotonicity is consistency, not an
independent physical clock. Independent custodian time and operating-key custody remain
KAN-131 production gates. The original red probe and exact review report are retained in
evidence-runs/review-20261011/opus-receipts/final. Source documentation now states that boundary.

F03 integrity is checked by content hashes. Atomic no-follow protections against hostile
parent/junction swaps are not implemented. Protected custody/identities, enrollment
rotation/revocation and authenticated scaling snapshots remain separate operating gates;
the tests here make no production credential-isolation claim.
