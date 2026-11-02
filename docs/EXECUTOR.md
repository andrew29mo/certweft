Current installed-package qualification is documented separately in
[INSTALL.md](INSTALL.md) and [DEPLOYMENT_VALIDATION.md](DEPLOYMENT_VALIDATION.md).
The source-run/transient milestones below retain their recorded scope.

# P0-2: privileged writer and executor takeover

Current [opening-intention rules](OPENING_INTENT.md) add a shared admission guard
and refuse the old direct normal-executor recover-request route. The historical
automatic-recovery descriptions below are not current behavior.

**Startup-policy update:** [RESTART_GATE.md](RESTART_GATE.md) supersedes the
earlier automatic process-recovery/reopening descriptions below. Old report
counts and source hashes are historical. Current source validation uses the
gate and storage runners plus Linux unit tests.

The current normal activation API is submit/request-status/cancel as specified in
[OPERATIONS.md](OPERATIONS.md). The synchronous activate examples below describe
the explicitly enabled legacy regression fixture, not the current default API.

## Implemented boundary

The production modules are certweft.service and certweft.executor. The Linux-only
root writer opens configuration with O_NOFOLLOW, checks the opened inode and
loads one immutable in-memory snapshot. Parent path components must be root-owned
and not writable by others, except root-owned sticky directories. The configured
Nginx executable must be a root-owned, non-writable regular file, not a final symlink.
Children receive the verified snapshot through stdin and do not reopen its pathname. It exposes
one Unix socket owned by a configured controller UID (0600), verifies SO_PEERCRED,
and accepts only status, activate and administrator-only recover. Activation
contains PEM bytes, epoch and revision, never a caller path, key, Nginx command,
CA URL or service selector. Unknown fields are rejected. This is a small source-run
service, not yet an installed systemd deployment.

The executor checks protected store and target ownership/modes, copies candidate
bytes to its private store and invokes the formal validation/activation backend.
The controller cannot mutate the journal, selected fragment, key, Nginx config or
lease file; the VM tests actual denied writes and direct nginx reload. Another
unconfigured UID cannot connect. No provisioner credential is passed to the writer.
The controller UID is a trusted local operator, not an anonymous remote tenant.

## Lifetime and async side effects

A separate fixed lifetime.lock inode is root-owned 0600. The root parent acquires
an exclusive nonblocking flock before replacing/listening on the socket. Each
real exec executor inherits the same open-file-description using pass_fds; neither
process calls LOCK_UN. Parent death therefore does not release the lease while
the executor remains alive. A replacement exits rather than waiting, bypassing
or recreating the lock. The core journal lock remains a second, inner lock.

Only the executor selects a version and sends reload. The fixed backend runs
nginx -t, then checks the configured master PID start time and executable before
sending SIGHUP through an opened pidfd. It does not launch a potentially delayed nginx -s reload
helper. Validation subprocesses do not publish or send signals. Master replacement
requires trusted administrator reconfiguration; PID reuse is not accepted.

A normal request allows 20 seconds for the executor, which runs in a separate
process group. On timeout the parent kills the whole group and allows 3 seconds
for communicate/reap. If that cannot finish, it exits fail-stop rather than
accepting more work; a still-living executor retains the lease. A real VM case
pauses the executor with a pipe-holding descendant and verifies group termination,
replacement recovery and new activation. D-state termination is not qualified. If a process does
not exit, no successful takeover should be promised. A sent HUP cannot be undone;
recovery still reconciles the committed version and requires fresh TLS evidence.
SIGTERM/SIGKILL of the parent is not graceful systemd shutdown; a surviving child
may finish the old operation while it remains the sole lease owner.

## Observed adversarial sequence

The VM uses real Nginx and an isolated OpenSSL CA fixture, not the step-ca
credential path qualified separately by P0-1. No TLS implementation is substituted.
Two CA-signed leaf versions use the same P-256 service key.

1. A root-only fixture checkpoint pauses the real exec executor after version
   selection using SIGSTOP. The checkpoint is absent from the controller API.
2. SIGKILL terminates the parent. A new root writer fails to acquire the lease.
   The pending durable APPLYING state and selected pointer remain unchanged.
3. SIGCONT lets the old executor finish and exit. Only then can replacement
   acquire the lease. It performs formal recovery and activates a new version.
4. An old epoch/revision request is rejected; fresh TLS confirms the new leaf.

This proves exclusion of a living orphan executor in the exercised sequence.
It does not claim a delayed old executor can coexist with a new writer and is
magically revoked: the design prevents that coexistence by keeping the lease.

## Tests and evidence

Run in a disposable Linux VM with root, Python 3.12, OpenSSL 3, Nginx, runuser,
existing nobody/daemon identities and unused loopback port 19444:

```sh
python3 -m unittest discover -s tests -v
sudo timeout 150 python3 tools/executor_vm.py
```

The runner starts the actual module service and actual subprocess executor. It
currently requires twelve VM cases and twenty-six separate unit tests (the earlier
P0-2-only suite had thirteen) at this stage. Current
[JSON](../evidence/executor.json) and [HTML](../evidence/executor.html) contain the
same result and source hashes. Source changes, errors, nonzero exit, timeout or
cleanup failure are not passing evidence. Prior reports are retained separately.
The first two runs exposed an invalid self-signed test trust topology; it was
replaced by a genuine CA/leaf topology without bypassing verification.

Owned writer processes are waited/reaped; Nginx master/workers and the orphan
executor must no longer run before success. An exited zombie awaiting PID 1
reaping is not treated as a live writer; its file descriptors are already closed.
Private keys, root config and raw logs remain only in root-protected VM fixtures
under /var/tmp/cw-executor-*. Do not upload those directories.

## Remaining MVP gates

- Persistent request deduplication, cancellation and durable end-to-end deadlines.
- Journal schema hardening, bounded subprocess output, history/GC and repair API.
- Formal installed package/systemd lifecycle, timeout/D-state tests, VM reboot.
- Concurrent master replacement, malicious host root and arbitrary root programs
  ignoring advisory locks are outside this trust model.
- No power-loss, zero-gap boot, all-client continuity or production-readiness claim.

P0-1 and earlier activation reports retain their source-bound historical scope;
this new report does not requalify all their cases under a persistent deployment.

## Independent P0-2 review

Two read-only reviewers identified configuration pathname substitution, an integer
PID signal race, unbounded timeout pipe cleanup, a generic nonzero-exit lease
assertion and a disk-only activation oracle. Corrections pin configuration bytes,
reject unsafe hierarchies/executable symlinks, use pidfd signalling, kill/reap the
executor group, require lease_busy/exit 73 plus inherited FD inode identity, and
check new TLS fingerprint/HTTP through an independent probe.

VM cases challenge root-owned configuration in a writable directory, replacement
of its pathname after service start, and an executable symlink. The latter is
rejected before any execution. These are boundary tests, not a claim of having
executed a root exploit or forced actual kernel PID reuse. The pidfd call path
has a unit regression and is used by actual VM reloads. The timeout uses the
real 20-second production setting, not a shortened test constant.

Earlier eight-case reports remain historical under executor-attempts. P0-1 reports
also retain their original source-bound scope; they are not new deployment tests.
