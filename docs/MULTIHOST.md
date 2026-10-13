# Authenticated cross-host deployment

API, custody and role service commands accept `--tls-cert-file` and
`--tls-key-file`. Supply both PEM files; incomplete or invalid configuration
refuses startup instead of falling back to HTTP. The private key remains on
the listening host. HTTPS uses TLS1.2 or newer and accepts only HTTPS Origin
values matching an enrolled Host. Bearer credentials, role authorization,
body limits and independent evidence-key pins remain required.

For a private operator-managed deployment, issue a server certificate from an
independently retained private CA with the actual hostname/IP in its SAN.
Configure clients with that CA through their private process trust store
(`SSL_CERT_FILE` for the Python client process). Do not disable certificate or
hostname validation, publish private keys, or install a test CA globally.

Example for an enrolled gateway:

```powershell
closure-engine api-serve --deployment PRIVATE_STATE --expected-trust-hash PIN `
  --credentials PRIVATE_AUTH_DIRECTORY --bind PRIVATE_INTERFACE --port PRIVATE_PORT `
  --allowed-host HOST:PORT --tls-cert-file SERVER_CERT --tls-key-file PRIVATE_SERVER_KEY
```

Container-internal HTTP remains supported for the existing isolated networks;
that compatibility does not authorize transmitting bearer credentials over
unencrypted external links. Multi-host verification needs two actual machines,
an authenticated client on the receiving host, an independent public enrollment
pin, the exact artifact/contract binding, and a fresh signed transaction
reconstructed from downloaded history/evidence. Merely opening a port is not
the receiving gate. Keep target/broker signing credentials off the AWL receiver.

The local TLS socket suite tests trusted HTTPS, unknown CA, wrong certificate
hostname, cleartext refusal, bearer refusal and HTTPS-only origin enforcement.
Actual cross-machine execution receipts are retained separately from those
same-host protocol tests. Single-host Runtime execution still holds its role
keys on that host; distinct machines alone do not establish distinct operating
identities for every role. Use the separate custody/role services for that boundary.
