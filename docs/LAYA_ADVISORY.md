# Laya scope decision

Decision: leave Laya out of Phase 0 dependencies and the verdict path.

The owner offered the exact model https://huggingface.co/convaiinnovations/laya on 2026-10-11, conditionally on useful value. The model card describes typed text classification/decisions, not free-text generation. The repo-root English checkpoint has a 512-token context; routing can select different family checkpoints, which would not be this exact requested checkpoint. These are publisher claims, not local benchmark results.

Phase 0 already has structured contract fields, signed typed observations and exhaustive deterministic admission rules. A probabilistic classifier adds no required function to those rules. It would introduce model/runtime downloads and an additional uncertain decision source without closing a current acceptance gap. No inference was run, no weights downloaded and no improvement is claimed.

A later optional experiment could classify short, sanitized human narratives for advisory triage before contract approval. Its inputs would be text/structured diagnostics, not screenshots; its output would be suggestions without execution, approval, verifier or verdict authority. Any admission would require a held-out comparison against explicit deterministic baselines, with false negatives, runtime failures and model-version/checkpoint identity retained separately. That experiment is deferred, not added speculatively.
