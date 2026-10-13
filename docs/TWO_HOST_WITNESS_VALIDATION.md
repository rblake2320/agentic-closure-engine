# Physical two-host temporal assurance validation

`tools/verify_multihost_witness.py` runs the shipped ACE runtime on Windows and the shipped
TLS temporal witness on an existing operator-approved Linux SSH host. It uses the same strict
SSH and certificate helpers as `tools/verify_multihost.py`; keep both scripts together.

The controller requires an independently supplied exact wheel digest and dependency lock:

```powershell
C:/Python312/python.exe tools/verify_multihost_witness.py `
  --ace-wheel <exact-candidate-wheel> --ace-sha256 <independent-sha256> `
  --lock <requirements.lock> --out-dir <NEW-evidence-directory> `
  --ssh-alias spark2 --remote-parent /home/rblake2320 `
  --bind 192.168.12.220 --port 18762
```

Use only an SSH alias whose host key is already authenticated. The controller passes
`StrictHostKeyChecking=yes`, `BatchMode=yes` and a bounded connection timeout. It refuses
non-private, loopback, multicast and link-local remote addresses. It creates a new
`ace-g3-witness-*` directory immediately beneath the remote user's home and changes no global
trust store, account, ACL, firewall rule, service, package installation or existing data.
The listed excluded PID and soak ports are reserved in the controller as well.

Both hosts create fresh virtual environments, install hash-locked dependencies, install the
exact wheel without resolving dependencies again, and compare every imported package file
against that wheel. The Linux witness generates its own persistent signing key and TLS leaf
private key. Windows receives the signed public manifest through the authenticated SSH path
and pins its digest **B** independently from the local authority trust digest **A**. Only a
new scoped witness-client bearer credential, the public enrollment and a certificate request
cross back to Windows. The signing key and leaf private key stay on Linux. The temporary
private certificate-authority key stays on Windows; its public certificate is used by the
client, with hostname and chain verification enabled.

The Windows runtime's operator-held profile requires the pinned witness before authority
events and acceptance can append. The following registered checks use actual target HTTP
operations, real signed events and persisted receipt/journal state:

| Check | Receiving outcome |
|---|---|
| Valid correction | Target artifact changes; verdict `PROVEN`; owner `ACCEPTED`; two required receipt sidecars replay |
| Wrong independent B pin | Public replay refuses `WITNESS_PIN_MISMATCH` |
| Wrong operator B pin | A fresh runtime refuses startup; original profile bytes and ledger head are restored unchanged |
| Edited receipt signature | Public replay refuses `WITNESS_SIGNATURE_INVALID` |
| Witness process stopped | Acceptance refuses typed unavailability; historical packet and ledger head remain unchanged |
| Same witness restarted | Same signer/DB pin; exact pending signed event and nonce reconcile once; second retry adds nothing |
| Protected invariant damaged | Actual target changes to invalid protected state; verdict `DISPROVEN` |
| Actual recovery | Child deployment restores the exact parent baseline bytes; parent `RECOVERED` |
| Recovery receipt removed | Removing each required parent/child/recovery receipt separately is refused |
| Silent TCP peer before TLS | Authenticated concurrent checkpoint completes; silent peer expires; untrusted CA refuses handshake |
| Offline export replay | New `python -I` verifier process receives only public wrapper and independently supplied A/B/bindings after both services stop |
| Published portable-v2 proof | The unchanged real 0.3.1 golden proof still verifies with the candidate's shipped CLI |

`registration.json` freezes expectations and tool/wheel digests before mutations. Phase logs,
public wrappers, installed-byte inventories and `handback.json` retain actual outcomes. The
controller stops only recorded PIDs whose `/proc` start ticks and command paths match the
new remote directory, and retains all owned state. It never prints bearer or private-key
contents. Evidence directories contain scoped credentials/private runtime state and must
remain operator-private; only the `windows/public` proof packages and public results should
be distributed. Earlier failed attempts remain separate from subsequent repaired runs.

This establishes physical host separation for the witness signer and OS clock. It does not
turn that clock into absolute UTC or remove the common administrator. The verified wrapper
states `ENROLLED_WITNESS_SYSTEM_UTC_NOT_ABSOLUTE_UTC` and reports historical assurance, not
present target drift. Existing portable-v2 proof bytes and their technical verdicts remain
unchanged. Consumers that require temporal assurance must independently pin A and B and
invoke the time-assurance verifier; ordinary portable verification alone does not imply this
additional policy.
