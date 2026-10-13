# Offline release publisher attestation

`tools/release_manifest.py` is a standalone companion asset. It imports Python's
standard library and `cryptography`, never ACE, AWL, an agent harness, or a model.
Use Python 3.12+ and the pinned `cryptography==50.0.2` dependency from the release's
hash-locked `requirements-runtime.lock`. Distribute the exact companion script
beside the product wheel, recipe, lock, CycloneDX SBOM, and signed manifest.
A consumer needs an independently authenticated copy of the verifier first;
executing an attacker-supplied verifier cannot establish trust in that verifier.

This signature means **the enrolled publisher attests to these bytes and source
identifiers**. It does not prove a reproducible build, truthful SBOM contents,
operating-system isolation, or compliance. Source commit/tree identifiers are
verified against a clean checkout at issuance, not reconstructed during offline
verification. Review/build/test attestations remain separate evidence.

## Publisher enrollment and separation

The operator supplies a dedicated Ed25519 PKCS8 PEM private-key file outside the
bundle, plus a public publisher profile outside the bundle:

```json
{"schema":"ace.publisher-profile.v1","purpose":"ace.release.publisher.v1","publisher":"example-publisher","public_key":"BASE64_RAW_32_BYTE_PUBLIC_KEY","runtime_key_exclusions":["BASE64_RAW_RUNTIME_PUBLIC_KEY"]}
```

The required publisher pin is `sha256:` plus the SHA-256 of the profile's UTF-8
JSON with keys sorted, no whitespace, `ensure_ascii=False`, and finite values.
Authenticate that pin through a separately controlled operator channel. The
profile itself must be supplied separately; copying a profile out of the bundle
never makes it a trust anchor. All fields, including runtime-key exclusions, are
covered by the profile pin. No key contained in a manifest becomes trusted.

The publisher signs `ACE-RELEASE-PUBLISHER-V1\0` followed by that same deterministic
JSON encoding of the payload. Runtime verdict signatures cannot substitute for a
publisher signature. Both commands reject publisher keys equal to any enrolled
runtime exclusion. Populate that inventory from the complete operator-controlled
public runtime-key inventory. An empty list explicitly means no runtime keys are
enrolled in this deployment. Ed25519 bytes do not reveal historical key reuse:
undisclosed reuse cannot be detected from mathematics alone. This tool does not
discover or borrow runtime keys and does not provision production publisher keys.

Keep publisher key custody separate from runtime/service keys, with operator-only
read permissions (POSIX mode0600 required; Windows ACLs are operator-managed).
Publisher profile rotation/revocation is an operator trust decision: distribute a
new authenticated pin and profile; retire the old pin in each consumer. Do not
silently trust a new key delivered in a release. Preserve the per-publisher
consumer high-water state across rotations. A compromised publisher can attest
false metadata; independent source/reproducible-build review is a separate gate.

## Closed bundle

Exactly these five distinct assets plus `release-manifest.json` are admitted:

- One product `.whl` (at most512MiB, SHA-256 and complete byte length).
- Exact committed build recipe, for example `pyproject.toml`.
- Exact committed dependency lock, for example `requirements-runtime.lock`.
- CycloneDX1.5/1.6 JSON SBOM.
- The companion verifier's exact bytes.

No extra files or empty directories, case-fold collisions, hardlinks, symlinks,
Windows junction/reparse paths, traversal, device names, or alternate-stream paths
are accepted. Files are not extracted or executed by verification. The manifest
is bounded128KiB; SBOM16MiB; directory64files/64directories. Operate on a quiescent,
operator-controlled directory: checks reject unsafe links, but are not a sandbox
against an administrator racing filesystem replacement. Keep downloaded assets in
restricted custody until verification and prevent mutation before use.

SBOM `metadata.component` must identify the wheel Name/Version and contain its
exact SHA-256. The issuer derives a signed canonical product from wheel METADATA Name (lowercase,
with runs of hyphen/underscore/dot normalized to hyphen). It accepts no arbitrary
product-label argument. Consumer selection requires an independently supplied
`--expected-product`, and the signed product must also match the actual wheel.
A publisher can sign multiple products without letting one substitute for another.
The signed release version must equal the wheel METADATA Version
at both issuance and consumption; contradictory correctly signed publisher claims
are refused as `RELEASE_VERSION_MISMATCH`. Its `components` names must equal all direct `Requires-Dist` names
from the wheel's METADATA, including optional/marker declarations. The tool checks
this correspondence, not full CycloneDX schema validity or dependency contents.
Scope is exactly **product wheel and direct declared dependencies**; it excludes
host OS, Python, and transitive runtime packages. A full environment/container
SBOM is a different artifact and must not be advertised as covered by this SBOM.
Component versions and vulnerabilities remain publisher assertions.

## Issue

Commit the recipe and lock first. Checkout must be clean, including untracked
files; source HEAD and tree must equal both supplied pins. Copy recipe/lock bytes
from `git show HEAD:<path>` into the bundle (Windows checkout CRLF conversion must
not silently change the bytes). The product wheel should be built from that same
pinned source using the committed recipe and lock. The issuer verifies identifiers
and committed inputs; it cannot prove who built the wheel.

```powershell
python -I release_manifest.py issue --bundle C:/release-assets `
  --publisher-profile C:/operator/publisher-profile.json --publisher-pin sha256:PROFILE_DIGEST `
  --private-key-file C:/operator/publisher.private.pem `
  --source D:/checkout --source-commit COMMIT40 --source-tree TREE40 --version 0.4.0.dev1 `
  --artifact agentic_closure_engine-0.4.0.dev1-py3-none-any.whl `
  --recipe pyproject.toml --recipe-source pyproject.toml `
  --lock requirements-runtime.lock --lock-source requirements-runtime.lock `
  --sbom sbom.json --verifier release_manifest.py
```

Issuance refuses an existing manifest. To correct a candidate, prepare a new
closed directory; never replace previously published versioned assets.

## Verify and consume once

Before first consumption the operator creates a consumer state file **outside**
the bundle, with a trusted initial floor (use the already accepted version when
migrating, rather than resetting history):

```json
{"schema":"ace.release-consumer.v1","publisher":"example-publisher","product":"agentic-closure-engine","last_version":null,"last_manifest_sha256":null}
```

```powershell
python -I C:/trusted-tools/release_manifest.py verify --bundle C:/release-assets `
  --publisher-profile C:/operator/publisher-profile.json --publisher-pin sha256:PROFILE_DIGEST `
  --expected-product agentic-closure-engine --expected-version 0.4.0.dev1 --state C:/operator/ace-consumer-state.json
```

Successful verification consumes the version and atomically advances the state.
An exclusive OS lock serializes concurrent consumers. Use a separate state file
for each publisher/product pair; the state explicitly binds both. AWL and ACE at
the same version therefore advance independent counters. Wrong-product state and
old state with no product are refused, never guessed or automatically upgraded.
Migrate a legacy floor only after independently identifying its actual product;
do not reset previously consumed version history. A repeated or lower version
is refused; a missing state file is not silently initialized. The exact expected
version must also be supplied independently. Supported ordered versions are
`X.Y.Z`, `X.Y.Z.devN`, `X.Y.ZaN`, `X.Y.ZbN`, and `X.Y.ZrcN`, with canonical numbers.
If the process exits after updating state but before returning output, inspect the
stored manifest digest to reconcile; do not reset state and retry blindly.

Protect the consumer state and `.lock` sidecar. This local high-water file is not
an externally anchored anti-rollback service: an administrator who restores old
state can remove that local history. Preserve it with operator backups or an
independent monotonic store when privileged rollback is in the threat model.
The pin, expected product, expected version, and independently protected state are consumer inputs,
not untrusted bundle contents. Verification does not install or run the wheel.

Missing required CLI arguments are refused by argparse with exit2. Valid commands
return JSON status on success; typed refusal JSON on stderr and exit3 on
failure. No private key or arbitrary input text is printed. The test gate executes
copies of the distributed script from outside the checkout in isolated Python
subprocesses, with real keys/files/git, actual Windows junctions, and concurrent
verification. Retain installed-script receipts separately from source test claims.
