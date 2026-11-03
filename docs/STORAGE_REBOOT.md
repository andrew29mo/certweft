# Installed storage faults across normal VM restart

This stage extends the preserved-state reboot evidence with three persistent
faults: ENOSPC on a dedicated 32 MiB ext4 image, a read-only mount of that image,
and real SQLite FULL under the writer's configured pager quota. It does not
fill/remount the VM root filesystem or simulate physical media failure. The
repository remains Private with no selected license.

## Exact experiment

Each fault starts with a fresh fixture-owned installation of the actual wheel,
fixed Nginx/writer systemd services, real local Smallstep-signed certificates and
an independently checked COMMITTED initial update. The application state is
copied, while services are stopped, onto the dedicated image at the **same fixed
state path**. Package/unit bytes, paths and privileges are unchanged.

A real operator submit reaches the installed executor's existing root-only
`confirmed` checkpoint: the candidate is already served, but the journal remains
APPLYING and the request is not COMMITTED. The test stops that application
without rollback, then introduces the persistent fault and attempts formal
startup/recovery. Thus the installed boot matrix qualifies startup and recovery
of an uncommitted publication under a fault; it does **not** claim the fault was
injected at the microsecond of the original COMMIT. The separate source-service
storage matrix exercises actual runtime prepare/post-publication/cancel failures
against the same implementation, rather than substituting a test recovery engine.

The temporary systemd mount unit persists the image/ro option across guest
`systemctl poweroff` and host start. A mount UUID check ensures the same ext4
filesystem returned; the host records manager Stopped/Running and different boot
IDs. Before Nginx/writer startup, the exact shared journal observer verifies the
main journal, recovery journal, Gate, state/history and active pointer against
the pre-shutdown snapshot. It only reads those application files. This excludes
shutdown rollback being mistaken for boot recovery.

A synthetic observer plan is used for the explicit pre-reboot startup attempt in
the old boot. That output is removed before the real shutdown plan is recorded;
it is not counted as a reboot. The final report only pairs real kernel boot IDs
with host-side shutdown/start observations.

## Required outcomes

| Fault still active after boot | Required evidence |
| --- | --- |
| ext4 ENOSPC | A real write fails with errno 28 before and after boot; the current writer invocation records errno 28 at Gate persistence and fails under its bounded restart policy; management/root CLI cannot report success |
| Read-only ext4 | A real write fails with errno 30 before and after boot; the current writer invocation records errno 30 opening its lifetime lease for writing; management/root CLI cannot report success |
| SQLite FULL | The service remains available but closed; a valid new request is rejected, and the formal root certificate verifier fails at storage validation with SQLITE_FULL, restored=false and updates_enabled=false |

**Management unavailable is not a persisted Gate transition.** With ENOSPC or
read-only storage, the old Gate can still say RUNNING because a replacement
record cannot be written. No live writer is accepting operations; a stale file
is not current admission permission. After storage repair, a new service session
must still refuse updates until the explicit root workflow completes. A valid
candidate/current-CAS submission actually checks this denial; the test does not
rely only on a status flag.

The candidate remains online while the fault is present. The selected exception
records bind the current boot/unit/invocation; stage matching is an executable assertion, not a full raw traceback archive. A failed
command is neither a rollback nor evidence that the committed certificate is
served. The report checks the candidate's exact leaf fingerprint during the fault, then
checks the exact committed leaf after root recovery.

## Repair and stale-operation controls

Only owned fault fixtures are removed: filler files, read-only mount option, or
allocation triggers/quota configuration. The Gate, journal, history and lease
are retained. SQLite FULL uses real allocation triggers, not a SQL RAISE()
substitute; the repair removes those test objects rather than rewriting history.

After verifying this boot's immutable observer result, the fixture detaches its
once-per-boot observer dependency before remounting storage for repair. This
prevents a mount stop from making the observer rerun and overwrite its evidence.
The sole writer test drop-in then requires the state mount. Runtime checks bind
the exact installed base unit, expected drop-in bytes, live command/cwd, root
UID, CAP_CHOWN and NoNewPrivileges. The Nginx unit is never edited.

Once writable, the restarted writer still denies updates. The installed root CLI
must complete persisted certificate restoration, journal reconciliation, opening
intention, fresh release preparation and paired opening. The old pending request
must become INTERRUPTED, not replayed or declared COMMITTED. Full normal/root
catalogs preserve old identity and timing fields and every terminal row. The
preboot Gate authority is explicitly rejected while still closed; current root
authority positively prepares VERIFY_REQUIRED. The SQLite old failed prefix is
then retried in that state and must read its original FAILED history without
changing Gate/catalog/core/wire, before a new recovery prefix is allowed. An old
core CAS request must fail without changing core/wire, while the same valid candidate with
a fresh CAS token must really COMMIT and present its exact new leaf on a new
trusted TLS/HTTP-200 connection. Issuance was completed before the fault; this is
actual activation after repair, not a new CA issuance/network-availability test.

The existing finite limits remain. Each fault is a fresh installation rather
than a claim of unlimited recovery in one store; SQLite-fault attempts consume
additional root history. No capacity reset or rollover is implemented.

## Reproduction and cleanup

Provision an already running disposable Colima VM per INSTALL.md with the
checkout mounted at the same path and Colima/Docker on the host PATH. The fixture
refuses an existing storage-reboot lab or conflicting mount/unit paths; it does
not erase unknown state. Its deployment bootstrap can reset only its previously
marked evaluation installation.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/storage_reboot_host.py \
  --profile <explicit-disposable-profile>
```

The driver runs bootstrap, `storage_reboot_vm.py prepare <fault>`, normal guest
poweroff/start, `check <fault>` and `cleanup <fault>`. A nonzero exit, timeout,
missing phase, source change or failed cleanup is not passing. Failed attempts
are retained; inspect the known lab and unit state before retrying. Do not use
forced/lazy unmount to manufacture cleanup success.

Cleanup requires stopped/empty service cgroups, an unmounted image and detached
loop device; temporary mount/observer/drop-in units are removed and the original
fixture state is restored for the next controlled installation reset. The host
restores the prior Docker context even on a failure. Private CA/state/image files
are not uploaded.

See [STORAGE_REBOOT_REVIEW.md](STORAGE_REBOOT_REVIEW.md) for the corrected
old-prefix, historical-row and failure-cause controls.

## Results and boundaries

All three installed fault/reboot/repair cases passed, together with 129 Linux
unit tests (zero failed/errors/skipped), eight installed deployment regressions
and 14 source-service runtime fault scenarios at the same 59-file manifest. Each
fault's bootstrap repeats the four installation/issuance/activation setup cases;
these overlap the deployment matrix and are not independent benchmark trials.

| Fault | Admission while faulted after boot | Post-SSH check/repair sequence | Writer RSS after repair |
| --- | --- | --- | --- |
| ENOSPC | No management endpoint | 3.983 s | 21,652 KiB |
| Read-only | No management endpoint | 4.260 s | 21,656 KiB |
| SQLite FULL | Management closed; root storage validation failed | 4.406 s | 21,656 KiB |

The initial attempts found a harness descriptor-lifetime defect (SQLite context
exit does not close a connection) and a one-shot observer dependency conflict
when its required mount stopped for repair. Explicit closing plus an FD test
with garbage collection disabled fixes the former; detaching the verified
observer dependency without overwriting its result fixes the latter. Both failed
attempts remain archived and are not counted as passing fault matrices.


The source-bound `storage-reboot.json/html` and `storage-reboot-host.json/html`
record the actual outcomes, root step histories, live identity, old/fresh request
results and cleanup. Host and VM boot IDs and the final VM report digest must
match. The host repair/check duration begins after SSH is available and includes
verification, service stops/restarts, repair and root recovery; it is not boot or
certificate-restoration time. RSS is a VM writer sample, not host/process-tree
memory or a sustained leak test. An unavailable service has no meaningful live
RSS sample; it must not be reported as a memory improvement.

Sudden power loss, boot zero-gap, arbitrary filesystem/device EIO, corrupt media,
external CA/network continuity and long-running resource stability remain
unqualified. Capacity exhaustion/runbooks and bounded sustained operation are
still the next closeout; this stage adds no application feature or license.
