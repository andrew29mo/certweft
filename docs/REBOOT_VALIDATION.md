# Installed-service boot and preserved-state recovery

This stage qualifies one installed Certweft 0.0.2 wheel on the provisioned
Ubuntu 24.04 ARM64 / systemd 255 VM used by the deployment milestone. The VM is
normally powered off with guest `systemctl poweroff`, then started again. This is
not a sudden power-loss test, boot zero-gap test, or storage-fault-across-reboot
qualification. Long-running stability and capacity closeout remain separate.

## Operational contract

Enable only the fixed writer after successful installation:

```sh
sudo systemctl enable certweft.service
sudo systemctl is-enabled certweft.service
```

Its existing `Requires`/`After` dependency starts the dedicated Nginx target before
writer identity validation. The signer is an explicit oneshot, not a boot job. The
local fixture CA is not required to restore an existing committed certificate;
new issuance still requires a reachable, authorized CA. Boot activation does not
mean updates are authorized. Inspect `certweft gate`, the actual endpoint and
request history before proceeding with the documented root recovery workflow.

A certified clean STOPPED Gate has its existing clean-start semantics. The three
fault-recovery cases below intentionally preserve a RUNNING Gate instead: they
must start RECOVERY_REQUIRED and refuse new updates. They do not redefine every
ordinary idle shutdown as an unclean application failure. A session that started
closed and was explicitly reopened still cannot obtain a clean STOPPED receipt
on later normal stop: restarting that recovered session intentionally requires
root recovery again. This consumes five of the finite 16 root rows each time;
three complete recoveries use 15 rows. There is no qualified root-history rollover
or automatic allowance reset. Inspect capacity before planning repeated recovery;
do not erase Gate/history or promise indefinite service restarts.

## Three preserved-state cases

1. **In-progress activation:** a real installed executor is paused at its existing
   root-only `confirmed` checkpoint, after candidate TLS verification but before
   COMMIT. The committed journal remains APPLYING. The main writer is also paused.
2. **Committed activation:** the actual operator CLI completes a different leaf
   update to COMMITTED. The writer is paused before normal VM shutdown.
3. **After explicit reopening:** the actual root CLI completes the paired recovery
   and reopening workflow. The writer is paused before another normal shutdown.

The deliberate process pauses prevent a clean shutdown receipt or application
rollback from replacing the evidence. systemd may forcibly end the stopped
processes after the existing stop budget; the VM shutdown itself remains orderly.
This is a fault-injected application within a normal machine shutdown, not a claim
about uninterrupted operation or physical power removal.

A disposable **read-only observer fixture**, required by a writer-only test drop-in
and ordered before Nginx, runs at the next boot. It records and compares:

- a different kernel boot ID and writer MainPID=0;
- exact main journal, recovery journal and Gate SHA-256;
- main state, normal/root request histories and active configuration symlink. The later checker also requires the observer
boot ID to equal the currently running kernel boot ID.

The observer opens both databases read-only, publishes its result with O_EXCL,
and fails startup on mismatch. It is not a second recovery implementation. Both
Nginx and writer still execute their fixed installed unit/package. There is no
Nginx drop-in and no relaxation of its byte/identity validation. The writer-only
observer dependency and observer unit are removed at the end of the test.

After boot, a valid fresh-CAS update is refused by the closed Gate. In the pending
case, **the candidate can remain online until explicit root recovery**; booting
management does not automatically roll back or prove restoration. The actual
root `certweft recover` restores the committed leaf, verifies new TLS connections,
reconciles the journal and explicitly reopens updates. The independent TLS probe
requires trusted localhost identity, the expected leaf and HTTP 200 on the same
new connection. Old core authority is then submitted through the real operator
CLI and must fail as Rejected without changing core state or the wire certificate.
The **same valid candidate** then receives a fresh request ID/current CAS token
through the same CLI, must become COMMITTED and present the exact different leaf
on a new trusted TLS connection. A blanket executor failure cannot satisfy both
controls. The normal request result exposes the error class, not a specific
stale-reason string; these paired controls isolate the authority change without
claiming an unavailable error detail. Previously COMMITTED
request history must remain byte-for-byte equivalent.

The existing finite bounds apply: 64 normal requests, 16 combined root requests,
16 generations. This three-case fixture consumes 15 root rows, so it is not an
unbounded recovery loop and must not be reused as one.

## Reproduction

The reproducible host driver records guest poweroff command status, manager
Stopped/Running observations and old/new kernel boot IDs, and cross-checks them
against each VM report. It restores the previous Docker context even on failure.
For an already running **explicitly disposable**, provisioned profile with the
checkout mounted at the same path, no existing reboot lab, and Colima/Docker on
PATH, run from the checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/reboot_host.py --profile <disposable-profile>
```

It runs the bootstrap and three cycles below. It does not create/provision a VM,
stop unrelated profiles or erase an existing diagnostic lab. A failed driver or
phase is not a passing run even if an older report exists. Report fields retain
sanitized decisions/IDs rather than raw host logs that may contain private paths.

The equivalent manual phases are:

Use a disposable VM provisioned per INSTALL.md, with the same checkout mounted.
Do not run against an existing production installation. `deployment_vm.py` owns
and resets only its marked evaluation installation; `--bootstrap-only` runs the
four actual wheel/install/issuance/activation cases and stops the CA and services.
The reboot runner refuses an existing private reboot lab instead of erasing it.

```sh
sudo env CERTWEFT_DEPLOYMENT_VM=1 PYTHONDONTWRITEBYTECODE=1 \
  timeout 300 python3 tools/deployment_vm.py --bootstrap-only
sudo env CERTWEFT_REBOOT_VM=1 PYTHONDONTWRITEBYTECODE=1 \
  timeout 45 python3 tools/reboot_vm.py prepare pending
sudo systemctl poweroff
```

From the host, confirm the selected VM stopped and start that same profile. SSH
can exit 255 when the guest powers off; neither that code nor an SSH timeout is a
passing recovery result. Require the next `check` command to exit zero and the
final report to say passed=true. Run inside the new boot:

```sh
sudo env CERTWEFT_REBOOT_VM=1 PYTHONDONTWRITEBYTECODE=1 \
  timeout 95 python3 tools/reboot_vm.py check pending
sudo env CERTWEFT_REBOOT_VM=1 PYTHONDONTWRITEBYTECODE=1 \
  timeout 45 python3 tools/reboot_vm.py prepare committed
sudo systemctl poweroff
```

Start the same VM and repeat `check committed`, `prepare reopened`, poweroff/start,
then `check reopened` and finally:

```sh
sudo env CERTWEFT_REBOOT_VM=1 PYTHONDONTWRITEBYTECODE=1 \
  timeout 35 python3 tools/reboot_vm.py finish
```

A timeout/failed phase leaves the report incomplete or failed, never a pass. Do
not advance to a later phase after failure. Keep private diagnostic fixtures in
the disposable VM. Reproduction requires a fresh lab or administrator inspection
and reset of known owned test paths, not blind deletion of unknown data.

## Observed result

All three preserved-state reboot cases passed. The host transcript also records all three manager-confirmed shutdown/start
cycles with matching boot IDs. The installed bootstrap’s four
cases, all 125 Linux unit tests (zero skipped), and eight installed deployment
regressions also passed at the same 57-file source manifest. Bootstrap overlaps
the deployment fixture and is not an independent performance trial.

| Preserved state | State seen before writer | Check/root-recovery/controls elapsed | Writer RSS after controls |
| --- | --- | --- | --- |
| Pending update | APPLYING | 3.097 s | 22,468 KiB |
| Committed update | READY | 3.244 s | 22,480 KiB |
| Reopened | READY | 3.233 s | 22,496 KiB |

These are single controlled observations with the scope below, not a benchmark
comparison or statistical bounds. Archived preparation failures included an
operator-unreadable public certificate fixture, reading the wrong SQLite catalog,
and an observer Nginx drop-in rejected by the formal identity guard. Later
pre-reboot harness changes invalidated earlier preparations. They are retained
as failed/invalidated evidence and not counted as reboot passes. SSH disconnection
on poweroff was separately followed by the VM manager reporting Stopped and a
different next-boot ID, not accepted as proof by itself.

## Evidence, measurements and limits

`evidence/reboot.json` and `.html` share an identical payload. The host driver
records its own JSON/HTML pair, final VM-report digest and matching source manifest.
The VM report now retains each boot’s actual loaded writer unit/command, live
cmdline/cwd, UID/capabilities, old/new boot and service IDs, closed-Gate rejection,
root step history, stale result and successful fresh-authority control. Writer
unit/drop-in bytes and package payload are checked again on every boot. The final report
binds source hashes and installed package payload hashes to the bootstrap wheel.
Archived failed/invalidated attempts are not passing scenarios. Negative observer
unit tests run the exact observer string and challenge changed shutdown state,
an already-started writer, duplicate evidence publication, wrong current boot,
and blanket activation failures/fake success without a changed TLS leaf.

The per-case elapsed value begins **after host SSH is available**, includes the
root recovery/check sequence and paired activation controls, and is not boot
duration, failover latency or an SLA.
The observer uptime is one early boot sample. RSS/VmHWM values are snapshots of
the writer in a VM, not host memory, process-tree peak or a memory-leak test. No
power-loss, filesystem durability under power removal, uninterrupted serving,
boot zero-gap, external reachability or production PKI claim follows.

Remaining closeout: storage faults across reboot and controlled repair; bounded
operation and resource/capacity limits. No new functionality is required by this
stage.
