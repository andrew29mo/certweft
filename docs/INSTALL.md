# Installed single-host deployment (P0-1/P0-2)

Qualified target: provisioned Ubuntu 24.04 ARM64, Python 3.12, systemd 255,
Nginx 1.24, Smallstep CLI 0.31.0 / CA 0.30.2. This stage tests installed
services and process restart. Preserved-state VM boot recovery is qualified separately
in [REBOOT_VALIDATION.md](REBOOT_VALIDATION.md).
The project is Private and has no selected license.

## Fixed scope and prerequisites

One dedicated Nginx unit/listener, one IPv4 loopback endpoint and the single DNS
SAN `localhost`; an existing P-256 service key and one pinned Smallstep trust
root. The `exploration` provisioner must already enforce the reviewed
[CSR policy](CSR_AUTHORITY.md) and claims. Installation does not inspect or
configure an external CA. Provisioner authentication permits same-identity CSR
reissuance, including issuance for another key; it is not possession-only renewal.
There is no scheduling, remote API, arbitrary unit selector or automatic key/trust
rotation. A trusted host administrator performs bootstrap and recovery.

Required OS packages: `nginx`, `python3-venv`, `python3-pip`, OpenSSL, and the
standard systemd/user-management tools. Install the pinned official ARM64
Smallstep binaries at `/usr/local/bin/step` and `step-ca` after verifying their
release checksum files. Do not fetch an unrelated package by running
`pip install certweft` from a public registry.

Use an isolated evaluation VM. The installer refuses existing managed paths,
units and account/group names; it does not upgrade or overwrite a running
installation. A partial installation is left for administrator inspection,
not silently declared complete or recursively removed by the product.

## Build and install the actual wheel

From the selected checkout, build a wheel in a build environment:

```sh
python3 -m venv /tmp/certweft-build
/tmp/certweft-build/bin/pip wheel --no-deps . --wheel-dir ./dist
sudo python3 -m venv /opt/certweft
sudo sh -c 'umask 022; /opt/certweft/bin/pip install --no-deps /absolute/path/certweft-0.0.2-py3-none-any.whl'
/opt/certweft/bin/certweft --help
```

The install umask allows the CLI/signer to read application code. Secret/state
permissions are separately fixed by the installer, not inherited from that umask.
Record the wheel SHA-256. Installed services run from `/`, use isolated Python
imports and load the wheel under `/opt/certweft`; they do not import the checkout.

Stage the initial valid certificate, existing P-256 key, pinned trust root and
provisioner password in a root-owned private directory such as
`/root/certweft-bootstrap`. Files must be root-owned regular files, not writable
by others, beneath protected parents. Never put password bytes in argv or an
environment variable. Then run:

```sh
sudo /opt/certweft/bin/python -I -m certweft.cli install \
  --certificate /root/certweft-bootstrap/baseline.pem \
  --key /root/certweft-bootstrap/service.key \
  --ca-root /root/certweft-bootstrap/root.pem \
  --credential /root/certweft-bootstrap/provisioner-password \
  --issuer-url https://localhost:19091 \
  --step /usr/local/bin/step --port 19443
sudo systemctl start certweft.service
sudo /opt/certweft/bin/python -I -m certweft.cli gate
```

Installation creates the fixed `certweft-operator` and `certweft-signer` non-login
accounts. It starts nothing until explicitly requested. Starting the writer also
starts its dedicated `certweft-nginx.service`; other Nginx units/configurations
are not modified. After validating the installation, explicitly enable boot startup
with `sudo systemctl enable certweft.service`. See REBOOT_VALIDATION.md for the
closed-Gate recovery contract and tested boundaries.

## Issue and activate

```sh
sudo systemctl start certweft-issue@trial-001.service
sudo runuser -u certweft-operator -- /opt/certweft/bin/certweft status
```

Copy `result.epoch` and `result.revision` from the current status into this explicit
CAS-bound request (replace the placeholders):

```sh
sudo runuser -u certweft-operator -- /opt/certweft/bin/certweft submit \
  --certificate /var/lib/certweft-candidates/trial-001/cert.pem \
  --request-id activate-001 --epoch <epoch> --revision <revision> --wait
sudo runuser -u certweft-operator -- /opt/certweft/bin/certweft request-status --request-id activate-001
```

`--wait` succeeds only for COMMITTED; admission/queue acceptance alone is not
activation success. TLS validation requires the intended leaf on three new
trusted connections with HTTP 200. Repeat a submit with the **same full body**
for deduplication; changed epoch/revision/timeout under the same ID is a conflict.
A client timeout is an unknown outcome: query history before choosing a new ID.
Cancel uses `certweft cancel --request-id ...`; accepted cancellation is distinct
from completed rollback, as in OPERATIONS.md.

Issuance is separate from activation. Each issue ID creates a new owned output
directory; a duplicate or partial directory is refused, never silently re-signed
or overwritten. Only the public signed certificate is group-readable to the
operator. Private key/provisioner password and writer journal are not readable
by that account. The signer receives the password via systemd LoadCredential,
runs without effective capabilities, and cannot read the source password file.
The signing unit has no restart policy; inspect a failure before retrying a new ID.

## Fault, repair and explicit reopening

A failed persistence operation may leave a candidate online. Do not infer rollback
from a nonzero client exit. Inspect request history, Gate and the actual endpoint.
To perform controlled repair:

```sh
sudo systemctl stop certweft.service
# Repair the underlying storage/permissions; retain the journal, Gate and lease.
sudo systemctl start certweft.service
sudo /opt/certweft/bin/python -I -m certweft.cli gate
sudo /opt/certweft/bin/python -I -m certweft.cli recover --prefix repair-001
```

The root helper executes the existing persisted certificate restoration,
closed journal reconciliation, opening intention, fresh release preparation and
explicit opening contracts. Each step has its original server deadline; reading
or replaying its history does not extend it. The helper waits for exact terminal
states and **current** live permission, not an old OPENED row. The CLI is a bounded
orchestration convenience, not a new durable workflow engine. An interrupted
cross-restart sequence can require a fresh explicitly authorized prefix; old IDs
are never recycled or rewritten. Query `recovery-request-status --request-id ...`
for individual `<prefix>-cert/journal/intent/release/open` outcomes.

Then issue another certificate, read a fresh core CAS token and submit it as above.
A repaired filesystem alone or restarting the service never reopens a recovered
store. Service restart closes such a store again by design, including a normal
stop/start after explicit reopening; that recovered session does not receive a
clean-stop receipt. Each repeated full recovery uses another five of the finite
16 root rows. There is no qualified history rollover/reset path. Do not manually clear
health rows, edit Gate files or unlink the lifetime lease to force admission.

## Supervisor boundaries

The writer remains a privileged root component, bounded to CAP_CHOWN; this is not
a root-compromise sandbox guarantee. It needs chown to transfer its 0600 socket to
the operator. Mode is set before ownership transfer, so CAP_FOWNER is unnecessary.
No CAP_SYS_PTRACE is granted. Installed mode binds the fixed root-owned Nginx unit
bytes, loaded command, MainPID, InvocationID and PID start time, then uses pidfd
for reload signals. The source-run `/proc/exe` mode remains separate. Unsupported
unit drop-ins or a changed master are refused; stop/reconfigure/start through the
administrator path. These checks trust the local systemd manager and host root.

`nginx -t` also opens its PID path, so the writer's explicit write allowlist includes
only its state/socket, dedicated Nginx runtime and log directories. Dedicated
Nginx temporary paths stay under its own runtime directory.

Writer policy: Restart=on-failure, RestartSec=1, three starts per 60-second window,
RestartPreventExitStatus=73, KillMode=mixed and TimeoutStopSec=8. systemd may kill
remaining cgroup processes after parent failure; the persistent lease additionally
prevents takeover while an executor outside that cgroup still owns it. Exit 73
requires investigation and explicit retry after the old owner exits, not an
infinite restart loop. After start limiting, `systemctl reset-failed certweft.service`
allows an administrator retry; it does not repair or reopen the application.

Stopping the unit must empty its cgroup. A sent signal is not evidence of process
exit. Uninterruptible D-state processes, hard realtime stop/recovery bounds and
machine/power failures are not qualified here.

## Storage unavailable across restart

With a full or read-only state filesystem, startup can fail before creating a
management endpoint or persisting a new Gate. An old RUNNING Gate file is not
live authorization. The still-running Nginx may serve the candidate; do not infer
restoration from a CLI error. Repair storage with the writer stopped, then use
the explicit root recovery procedure above. Storage repair and systemd restart
alone do not reopen an uncertain store. SQLite FULL may instead leave management
available but closed; failed root validation must not be treated as restoration.
The reproducible isolated fault matrix is in STORAGE_REBOOT.md. Its temporary
loop-image/mount/observer units are test fixtures, not an automatic production
filesystem-repair or deployment feature.

## Bounds and evidence

Limits remain 64 permanent normal requests, 16 combined root recovery requests,
and 16 immutable generation directories. A full recovery helper uses five root
rows. There is no automatic history or certificate GC/rollover; repeated recovery
is intentionally finite. Capacity exhaustion/rollover operational qualification
and long-running stability belong to the next bounded closeout, not this stage.

See [DEPLOYMENT_VALIDATION.md](DEPLOYMENT_VALIDATION.md) for the reproducible
isolated VM workflow, measurements, failures encountered and current source-bound
JSON/HTML. The separate reboot stage covers three preserved-state application faults within
normal VM shutdown/start cycles. [STORAGE_REBOOT.md](STORAGE_REBOOT.md) separately
qualifies ENOSPC, read-only and SQLite FULL across reboot and explicit repair.
Power loss, boot zero-gap, all-client continuity, arbitrary media failure and
general production readiness remain unqualified.
