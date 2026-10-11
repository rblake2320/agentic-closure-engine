# Repository instructions

Read `C:\dev\engineering-standards\CONSTITUTION.md` and inherited drive instructions before work.

The owner approved design commit 7e7a503 on 2026-10-11 with "do it" and authorized Phase 0 implementation, Jira progress tracking, the session registry update, and GitHub repository creation. See docs/APPROVAL.md. Implement and test the offline kernel; the design-review gate is released.

The owner's 2026-10-11 directive supersedes the earlier offline-only scope: build complete,
independently usable products with shipped producer/runtime commands, persistent identities,
real outcome observation and recovery, user interfaces, and dedicated local container deployment.
Mocks, fake outcomes and unshipped fixture scripts do not satisfy product acceptance. Existing
production targets, paid cloud resources, credential discovery, shared databases, and host
account/ACL changes remain excluded. Root coordinates isolated source lanes and tracker edits.

AI is excluded from technical verdict evaluation. Test valid controls alongside adversarial cases. Keep technical verdict, operational decision, evidence admissibility, and recovery outcome distinct.

Capture machine evidence for tests actually run. Design matrices contain planned checks and must never be reported as executed results. Keep private keys and runtime evidence out of version control.
