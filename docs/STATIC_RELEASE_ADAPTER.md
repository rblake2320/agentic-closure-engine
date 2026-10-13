# Static-file release adapter

This target publishes real HTML, CSS, JavaScript, images and JSON from a ZIP to an
operator-enrolled filesystem directory. It implements ACE target protocol v1, so the
existing broker, isolated verifier, deterministic closure authority and recovery flow
can use it without a new evaluator. It never runs archive content or deployment commands.

The module is shipped in the ACE wheel. Use the version containing this adapter; the
previously released 0.3.1 does not contain it. Source versioning and the subsequent release
are coordinated separately. The adapter's protocol remains v1.

## Build a real release

Create a directory containing `index.html`, the site's static files, and `release.json`:

```json
{"version": 2, "entrypoint": "index.html"}
```

Build and inspect a deterministic ZIP using the installed interpreter:

```powershell
python -I -m closure_engine.adapters.static_release pack --source customer-site --out release-v2.zip
python -I -m closure_engine.adapters.static_release checks > static-checks.json
```

The pack command reads actual source files, hashes the exact produced ZIP, refuses to
replace an output, and performs the same admission checks as deployment. No model or
AI harness is needed. UTF-8 JSON output redirection should be used on Windows PowerShell
5.1; for example, pipe to `Set-Content -Encoding utf8` instead of its UTF-16 default.

For first enrollment, create persistent ACE role identities using the existing `init`
commands, enroll the seven check IDs printed by `checks`, and retain the operator's
public trust hash independently. Enroll the target using the existing command:

```powershell
closure-engine target-enroll --deployment authority --target-id customer-static `
  --base-url http://127.0.0.1:8790 --checks static-checks.json
```

The command stores a private deployment credential in the broker root and returns only
its SHA-256 hash. Save that public `deploy_token_sha256` in `broker-token.sha256`.
Do not copy or print the credential itself. The adapter stores the hash only, no signing
key and no access to ACE custody or evaluator code.

Create a separate operator-controlled `site-policy` directory with `access.json` and
`retention.json`. These are actual externally read protected resources. Their bytes
must remain unchanged through deployment and observation. They must contain public,
nonsensitive policy because their probe routes are readable. Enroll an existing initial
ZIP; the target root must not already exist:

```powershell
python -I -m closure_engine.adapters.static_release init --root release-custody `
  --archive release-v1.zip --token-hash-file broker-token.sha256 --protected-dir site-policy
python -I -m closure_engine.adapters.static_release serve --root release-custody --port 8790
```

`http://127.0.0.1:8790/` now serves the actual `index.html`; nested assets are ordinary
HTTP resources. The adapter listens only on loopback. It is usable behind an operator's
separately secured same-host proxy; it does not provide public TLS termination or a
distinct-host listener. Root coordinates distinct-host verification independently.

## Freeze the outcome separately from the artifact

The primary acceptance conditions are the owner's desired `site-version` and exact
`site-content` SHA-256 of the intended `index.html` bytes. The artifact cannot choose
its own expected outcome. `/release-status` reads the active archive's manifest and
checks the actual served index bytes against that archive before returning its digest.

Use existing CLI lifecycle commands or the authenticated role-gated gateway. For example:

```python
import os
from pathlib import Path
from closure_engine.runtime import Runtime

# Pin is supplied independently, not trusted because it was returned with a proof.
authority = Runtime("authority", os.environ["ACE_EXPECTED_TRUST_HASH"])
authority.propose(
    "customer-static", "publish-orders", Path("release-v2.zip").read_bytes(),
    intent="Publish approved customer orders page",
    expect={"site-version": 2, "site-content": "sha256:YOUR_OWNER_APPROVED_INDEX_BYTES_HASH"},
)
```

Review and approve the frozen contract through the owner role, then freeze, baseline,
run the deployment and observation window, close and separately accept its PROVEN result.
The enrolled checks require two primary conditions, two protected-resource invariants,
exact active artifact read-back, staged artifact integrity and retained baseline custody.
Follow existing OPERATIONS and trust-boundary documents for separate operating identities;
running a local all-key CLI is administration, not independent operating-identity isolation.

## Activation and recovery

`PUT /ace/v1/artifact` requires one broker bearer header, one `If-Match` SHA-256, one
`X-ACE-Intent` and one decimal Content-Length. Duplicate framing/authority headers,
chunked bodies, foreign Host/Origin and missing preconditions are refused. A wrong current
digest returns 412 without changing state. The broker's existing write-ahead execution
receipt and read-back logic remain authoritative for the ACE transaction.

The adapter additionally writes its activation intent durably before creating a release.
Admission finishes before any file is created. All files and the exact ZIP are fsynced in
an unreferenced staging directory; a release directory is promoted atomically; activation
then replaces one `active.json` descriptor atomically. Readers see one complete old or new
release, never an incrementally overwritten live tree. An OS file lock serializes separate
processes and is released on process death. Duplicate applied intents are idempotent;
conflicting intent reuse is refused. A pending intent is reconciled as APPLIED or NOT_APPLIED
only from the current hash, generation and intent identity; an unexpected third state
quarantines startup and deployment. Interrupted staging is retained, never auto-activated.

For a failed deployed outcome, the existing `recover` child transaction sends the exact
original ZIP retained by ACE baseline custody. It does not recompress equivalent files.
Independent observations must verify both the restored primary values and original
protected bytes before ACE declares RECOVERED. If an operator or another service changed
the separately owned policy, that operator must restore its original bytes; publishing
an old site ZIP cannot restore or authorize changes to external policy. Recovery remains
failed until those original protected bytes are observed again.

## Admission and custody boundaries

| Boundary | Enforced limit/control |
| --- | --- |
| ZIP input | 524,288 exact archive bytes |
| Expanded data | 8 MiB total, 1 MiB per file, 128 entries, maximum 100:1 per-file ratio |
| Names | ASCII allowlist, length limits, no traversal, drive/ADS paths, backslashes, percent aliases, Windows device names or trailing dots |
| Aliases | Case-folded duplicate and file/directory-prefix collisions refused |
| File kind | Regular static files only; symlinks, special devices, encryption and unsupported compression refused |
| MIME | html/css/js/json/svg/png/jpg/jpeg/ico/woff/woff2/txt/webp only; `nosniff` and same-origin CSP |
| Filesystem | SHA-256 internal storage IDs; symlinks and Windows reparse points refused in existing components |
| HTTP | Bounded body, 10-second whole connection deadline, 32 admitted concurrent connections, structured refusals |
| Evidence | Actual public HTTP read-back; existing Ed25519 signed ACE receipts/observations/packets and public-only portable replay |

The state and policy directories must be owned by the operator and inaccessible for
actor writes. Path guards are defense in depth; they are not an OS sandbox against a
privileged process swapping directories between an inspection and open. Windows private
file modes are not ACL isolation. Configure operating identities/ACLs or service isolation
outside this module. Policy configuration is trusted enrollment, never archive input.
The target has no shell, interpreter invocation or authority to issue a closure verdict.

## Executable verification

From the repository, with the built wheel installed in a fresh interpreter:

```powershell
python -I -m pytest -o pythonpath= tests/test_static_release_adapter.py `
  tests/test_static_release_adapter_e2e.py --junitxml=static-release.xml
```

This gate executes real file admission, separate-process concurrent activation and an
actual killed process after an observed PENDING intent. It exercises real signed Runtime
transactions against a separately running target: successful publication, incorrect actual
HTML, an operator's actual protected-file mutation, two exact ZIP recoveries, HTTP readback,
restart persistence and public-only proof replay in another fresh process. No mocks.
Windows junction and Linux symlink tests are platform twins; the unselected twin is recorded
as a skip. This gate is same-host and bounded local execution, not a distinct-host or
large-scale load result. Set `ACE_STATIC_RELEASE_RECEIPT` to retain machine-generated
scenario results. JUnit and hashes establish which installed build was exercised.
