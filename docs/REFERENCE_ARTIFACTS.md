# Reference-target artifacts and operator roles

The shipped reference target accepts exact UTF-8 JSON bytes with one top-level
`routes` object. Each route maps to the JSON body returned by an ordinary GET.
For example:

```json
{
  "routes": {
    "/catalog": {"product": "Agentic Closure Engine", "version": 3},
    "/config": {"mode": "safe"},
    "/other": {"value": "stable"}
  }
}
```

The route names and protected responses above are illustrative. Read the actual
enrolled target's baseline artifact and contract first. Preserve each protected
route byte-equivalent according to its frozen observer; change only the owner-approved
primary outcome. A plain `{"version":3}` or `{"answer":3}` is not this artifact
format and the reference target refuses it. ACE never infers acceptance criteria
from the submitted artifact. Supply `expect` using the enrolled primary check ID,
for example `{"catalog-version":3}` only if that is the actual enrolled check.

Artifact size is measured on the decoded artifact bytes, before storage, with a
maximum of 524,288 bytes (512 KiB). JSON/base64 HTTP envelope overhead has a
separate request-body bound. Over either bound the API returns JSON with status
413. New external transaction IDs use ASCII letters/digits and `.`, `_`, `-`,
begin with a letter/digit, are at most 128 characters, and exclude `..`. `/recovery`
identifiers are reserved for server-created children; historical children remain
readable and verifiable.

The console's "global ledger" sequence and head represent all transactions.
Transaction status exposes `allowed_actions` and recovery eligibility; the console
filters these actions by the caller's authenticated roles. Signed deployment
receipts can contain a stable `reason_code` and the target's HTTP status. These
fields explain an operational failure without changing the historical deterministic
verdict or its mandatory-check precedence.

Runtime signer identities remain separate role keys/services. A convenience
operator bearer token granted every API role may request each service's operation;
it is an administrative delegation, not separation of human duties. For restricted
callers use the shipped `api-credential` command with a distinct principal and only
its required `--role`, a private `--token-out` path, and the intended credential
map. Do not publish the token, signing keys, or deployment credential. Validate each
new principal against `GET /api/v1/whoami` and a denied operation before allowing it
to perform consequential work. A viewer needs only `viewer`; an artifact proposer
needs `actor`; approval/acceptance uses `owner`. An operator can administer enrollment,
so enrollment custody is an explicit trust root, not a claim that administrators
cannot grant themselves authority.
