# Repository instructions

Read `C:\dev\engineering-standards\CONSTITUTION.md` and inherited drive instructions before work.

The owner has authorized a design package first. Do not add executable implementation, schema implementation, dependencies, integrations, or host security changes until the owner has reviewed the trust boundaries and state-transition invariants. A subsequent explicit approval referencing this design releases that gate.

Keep scope to the offline Phase 0 kernel. No production systems, agent-wire/SelfConnect integration, credential discovery, cloud resources, or OS-account/ACL changes without the applicable later authorization.

AI is excluded from technical verdict evaluation. Test valid controls alongside adversarial cases. Keep technical verdict, operational decision, evidence admissibility, and recovery outcome distinct.

Capture machine evidence for tests actually run. Design matrices contain planned checks and must never be reported as executed results. Keep private keys and runtime evidence out of version control.
