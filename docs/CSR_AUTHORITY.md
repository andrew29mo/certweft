# P0-1: CA-enforced CSR authority and credential delivery

## Contract

The dedicated `exploration` JWK provisioner accepts exactly one DNS identity:
CN localhost, a single DNS SAN localhost, no IP/email/URI SANs, serverAuth-only,
and an ECDSA P-256 public key. A CA request is prohibited. Its server-side
[template](../policy/server.tpl) uses `fail` to reject violations before signing;
it does not silently rewrite forbidden requests. The issued signature algorithm
is fixed to ECDSA-SHA256. This does not constrain a CSR's own signature hash.

Provisioner claims set minimum requested lifetime 5 minutes, default 30 minutes,
maximum 1 hour, disable renewal and disable SSH CA. The actual default certificate
has a 60-second CA backdate, so its observed notBefore-to-notAfter interval is
1,860 seconds. Requested duration and that interval are distinct. Requests for
1 minute and 2 hours are rejected by CA validity enforcement. SSH rejection and
malformed extension encodings have not been qualified in this slice.

The adapter creates an explicit serverAuth CSR using the existing key and uses
`step ca sign`; it never reloads Nginx. No local policy validation stands between
the malicious CSR and the CA in the negative tests. Each passing rejection case
requires new CA log evidence with its reason and HTTP 4xx, plus no output cert.
The root trust is pinned; no CA verification is disabled.

## Authority trade-off

This uses a provisioner credential, not possession-only certificate renewal.
A holder can mint another key for the allowed service identity until the
credential/provisioner is disabled or replaced. It is not cryptographically bound
to one host or existing key. The CA root and intermediate private keys, CA
configuration and CA-unlock secret remain outside the signer identity's access.
Disabling renewal avoids bypassing this signing policy via the separate renewal
route; this new policy does not fix the previously observed token-renewal issue.

The test provisioner has its own random password, different from the random CA
unlock password. Bootstrap/CA operation remains an administrator responsibility.
These test credentials are not production credentials. No general PKI admin API,
CA trust rotation, enrollment automation or external secret manager is provided.

## Delivery and evidence

The formal adapter `reissue_credential` receives only a password-file path through
systemd's CREDENTIALS_DIRECTORY. Actual secret bytes are not arguments or environment
values. A real transient service uses a separate non-login signer user,
LoadCredential, NoNewPrivileges and ProtectSystem=strict; only its private client
directory is writable. It calls the actual certweft.ca module and validates the
result against the CA root. This qualifies a one-shot credential path, not the
future persistent daemon, privilege-separated writer or orphan executor.

On this systemd build delivered credentials are 0440 root:root, with access scoped
by systemd's credential directory/mount. The adapter accepts root-group read
permissions but rejects public read/write and non-root group read. Source secrets
and raw CA logs are 0600; the CA directory is 0700. Real access checks require
both nobody and the signer to be denied source password, CA private keys and raw
CA logs; nobody is also denied the service key. The signer is intentionally able
to read its delivered credential and service key. Host root remains trusted.

Tests scan the transient command/captured output and service journal for the
random provisioner secret, and public report serialization must not contain it.
This is evidence for the exercised paths, not proof against root, memory dumps,
all process inspection, compromise of the signer, or arbitrary future logging.
Private CA logs may contain tokens and remain inside the VM; never upload them.

## Reproduce

Use the same disposable VM and prerequisites as [REPRODUCE.md](REPRODUCE.md),
with systemd-run, useradd/userdel/runuser, root, and unused port 19091. Keep
CW_STEP/CW_CA at the tested executable paths. From the checkout:

```sh
python3 -m unittest discover -s tests -v
sudo env CW_STEP="$CW_STEP" CW_CA="$CW_CA" timeout 180 python3 tools/policy_vm.py
```

[JSON](../evidence/policy.json) and [HTML](../evidence/policy.html) share the result.
The report is initialized as in_progress in both formats. Nonzero exit, timeout,
source changes, failed cleanup or an incomplete report is failure. Prior attempts
remain in evidence/policy-attempts. The first two runs rejected the systemd 0440
credential file due to an overstrict mode check; they remain failed, not passing.

The runner creates private fixtures under /var/tmp/cw-policy-*; it removes its
transient account, stops its own CA/service and verifies those resources are gone.
Private fixture files remain for diagnosis. Do not delete unrelated VM data.

## Materials

- https://smallstep.com/docs/step-ca/templates/
- https://smallstep.com/docs/step-ca/provisioners/
- https://smallstep.com/docs/step-ca/configuration/
- https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

The sources explain mechanisms; the report records the specific tested versions.
