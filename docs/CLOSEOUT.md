# Finite-capacity and bounded-operation closeout

Scope: one installed Certweft wheel, the fixed local Nginx/writer systemd units,
real fixture-CA certificates and operator/root CLI. The VM is isolated. This
adds qualification and an exhaustion runbook, not GC, history reset, rollout,
renewal scheduling or a new application feature. Private/no license is unchanged.

## Three independent boundaries

The host runner performs a fresh marked application installation before each
capacity case. None seeds SQL history or fabricates application generations.
The four bootstrap cases overlap the installed deployment matrix; repeats are
setup observations rather than independent performance trials.

| Boundary | Real workload used to reach it | Required result |
| --- | --- | --- |
| 64 normal requests | Initial real COMMITTED update plus 63 stale-core FAILED requests; only two real generations exist | New valid submit returns history_full without admission; original-body replay returns its old row, changed body conflicts; service restart retains count and refusal |
| 16 generations | Two bootstrap generations plus 14 actual successful alternating-leaf updates; normal history remains below 64 | Next valid activation fails without changing core/wire or adding a seventeenth generation; service restart retains the limit |
| 16 root requests | Sixteen actual verify-storage operations under a closed prepared Gate; normal history/generations stay small | Next root operation returns recovery_history_full; same-body history remains readable, conflicting reuse fails, service restart retains the limit |

Normal-history exhaustion separately requires a real five-step root recovery to
succeed using its independent root allowance. Existing history must remain
unchanged and normal admission must still fail at 64 afterwards.

The executor currently reports a generic Rejected error class for a generation
failure, not a version_capacity reason string. The VM uses a successful last-slot
control, a still-valid candidate, exact counts and unchanged core/wire; the unit
control also requires the actual backend's version_capacity rejection. This is
not evidence that all 64 normal operations were successful rotations: successful
rotations would encounter the smaller generation bound first.

## Root budget: 0–5 remaining rows

Each independent case first leaves a real confirmed-but-uncommitted candidate
online, crashes the actual writer, and verifies takeover remains closed. It then
uses real verify-storage calls to leave exactly 0, 1, 2, 3, 4 or 5 root slots.
The installed root recover CLI attempts the complete existing workflow.

| Remaining rows | Maximum completed steps | Admission |
| --- | --- | --- |
| 0 | None; candidate can remain online | Closed |
| 1 | Restore committed certificate and verify TLS | Closed |
| 2 | Also reconcile main journal | Closed |
| 3 | Also prepare opening intention | Closed |
| 4 | Also prepare fresh release | Closed |
| 5 | Also pair and commit opening | Open; a genuine subsequent activation must succeed |

There is **no five-row reservation transaction**. An insufficient budget can
complete some steps and then return recovery_history_full; those completed
steps are not rolled back. This is reported as partial progress, never whole
workflow success. Every partial case must refuse a real valid normal submit;
a stale runtime Gate authority can be its precise rejection after preparation.
The reported Gate remains closed. Each case snapshots the complete state before
its first service restart and verifies counts/history persist and admission is
closed again, including the recovered
session's existing conservative restart contract.

## Exhaustion runbook

Before a planned update/recovery, inspect request/generation counts and outstanding
operations with the journal retained. A complete new recovery helper needs five
unused root rows; failures can consume rows too. The product does not reserve
those rows or guarantee a later recovery will fit. Monitor the smaller remaining
allowance rather than planning against only the normal-request limit.

Use the installed CLI for live state and individual outcomes:

```sh
sudo /opt/certweft/bin/certweft gate
sudo runuser -u certweft-operator -- /opt/certweft/bin/certweft status
sudo runuser -u certweft-operator -- /opt/certweft/bin/certweft request-status --request-id <id>
sudo /opt/certweft/bin/certweft recovery-request-status --request-id <root-id>
```

This release has no new capacity endpoint. A trusted root administrator can
inspect bounded counts with read-only database connections (no repair/migration):

```sh
sudo /opt/certweft/bin/python -I - <<'PYTHON'
import json,sqlite3
from contextlib import closing
from pathlib import Path
root=Path('/var/lib/certweft');counts={}
for name,file,table in [('normal','journal.db','requests'),('root','recovery.db','recovery_requests')]:
    with closing(sqlite3.connect('file:'+str(root/file)+'?mode=ro',uri=True,timeout=.5)) as db:
        counts[name]=db.execute('SELECT count(*) FROM '+table).fetchone()[0]
counts['generations']=len(list(root.glob('v-*')))
print(json.dumps(counts))
PYTHON
```

These are separate read snapshots, not a cross-database reservation or permission
to proceed concurrently. A busy/error result is not a zero count. For deduplication,
retain the original full request body/CLI arguments; do not replace its old CAS
with current values under the same ID. If the body is unavailable, query history.

If a limit is reached:

1. Stop submitting new IDs and record the command's exact result. Query existing
   request IDs; a timeout is unknown outcome, not permission to try more IDs.
2. Check the live Gate and independent TLS endpoint. The candidate may still be
   served, and a failed helper does not prove rollback or complete restoration.
3. Preserve main/root journals, Gate/receipt files, generation directories and
   diagnostic evidence. Do not delete histories, unlink leases, manufacture clean
   receipts or edit the active symlink to reset allowances.
4. If fewer than five root slots remain, treat a new full recovery as potentially
   partial. Keep normal admission closed and escalate to the trusted host
   administrator; this release has no qualified automatic capacity recovery.
5. Stop/quiesce Certweft through the documented service procedure before offline
   maintenance. Preserve the existing installation. Replacing a production store,
   transferring authority/history or manual certificate repair is **not qualified
   by the disposable-fixture reset** used in these tests.

These capacity cases use service stop/start or writer crash takeover, not an
additional VM poweroff of a full-capacity store.

The tool is intentionally finite. This guide is a stop-and-preserve procedure,
not a validated production migration, rollover or reset recipe.

## 1200-second resource experiment

A separate fresh installation starts one writer/Nginx master invocation. The
observation spans at least 1200 VM-monotonic seconds with 121 quiescent samples
on a ten-second schedule. No restart, reset, fixture reinstall, forced collector call or history/generation
cleanup runs during that window. Ordinary Python/OS memory management remains
enabled. PID/invocation identity and restart counters are checked continuously.
All subprocess work is the installed CLI/executor and real TLS.

During the first 140 seconds, eight real successful updates, two accepted running
cancellations and four stale-core failures create a bounded history. A root-only
one-second confirmed-checkpoint delay makes the cancellation window reproducible;
it is not a performance configuration or latency comparison. Remaining cycles
query/replay old bodies, cancel already terminal requests and submit a malformed
new ID through the server, without growing history. Stable-phase evaluation begins
after 180 seconds, separating intentional initial data growth from steady work.

Thresholds are fixed in the source and initial report before measurement:

- Writer RSS span <= 4096 KiB; fitted growth across the stable window <= 1024 KiB;
  last-six minus first-six median RSS <= 1024 KiB. These allow bounded Python
  allocator variation but must reject a sustained observed trend above that bound.
- Writer FD span <= 2, one quiescent writer cgroup process, zero restarts.
- Nginx stable cgroup has exactly master + one worker with a fixed PID set;
  aggregate sampled RSS span
  <= 4096 KiB, median growth <= 1024 KiB and aggregate FD span <= 2, zero restarts.
- Unique-inode state logical/allocated bytes, file count and normal/root/generation
  counts must remain constant after warmup. Symlink targets are not double-counted.

The evaluator has counterexamples for growing RSS, FD growth, residual children,
restarts, repeatedly replaced workers and continued persistent-state growth.
Complete fixed-history catalogs are compared every steady cycle, at the end and
after stop; equal-size history rewrites must not pass. Thresholds do not imply a
zero
leak rate or long-term stability; a slower leak can remain below this window's
resolution. Main-process HWM and sampled cgroup totals are different observations,
not a measured complete process-tree lifetime peak. Summed per-process RSS can
double-count shared pages; it is not physical memory consumption. Controller, interpreter,
logs, issuer candidate-output directory, private CA and the VM/host disk
allocation are outside the state-disk count.

## Observed closeout result

All nine independent capacity cases passed. The resource observation completed
1200.182 seconds with 121 samples, 103 after warmup, without writer/master restart.
Writer RSS was 21,840–21,932 KiB in the stable window (92 KiB span), with fitted
growth 26.41 KiB and first/last-six median growth 32 KiB; FD stayed at 5. Nginx
cgroup RSS stayed at 13,432 KiB and total FD at 15, with the same two PID set after
warmup. State logical/allocated bytes stayed at 81,967/212,992 (43 regular-file
inodes); normal/root/generation counts stayed 15/0/12. Creation, final and
post-stop full catalogs were identical, and all 107 steady-cycle history checks
passed. First and final restart snapshots in all nine capacity cases also
preserve every new recovery/activation record. These values passed the
original thresholds and are not a zero-growth or leak-free claim.

The actual workload contains eight COMMITTED updates, two ROLLED_BACK running
cancellations and four FAILED stale-authority requests. Ordinary Nginx worker
replacement during the successful warmup reloads is part of activation; the
post-warmup PID set did not change. After that finite creation phase, 107 cycles
reuse fixed history through queries, duplicate bodies, terminal cancellation and
server rejection of invalid new IDs. This is a modest scripted control-plane
workload, not continuous rotations, a load benchmark or a long-term soak.

See [CLOSEOUT_REVIEW.md](CLOSEOUT_REVIEW.md) for the corrected first-restart
history snapshots, worker identity and full-catalog controls.

## Reproduction and evidence

Use an already running explicitly disposable, provisioned Colima profile with the
checkout mounted at the same path, per INSTALL.md. The deployment fixture resets
only its marked evaluation installation; never run against production state.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/closeout_host.py \
  --profile <explicit-disposable-profile>
```

The driver runs nine independent capacity cases, then the 1200-second observation
with a separate installation. Raw host output/private paths are not uploaded.
JSON/HTML reports begin in_progress/passed=false; a timeout, failed phase, source
change or failed cleanup is not passing. The host records final capacity/soak
digests and restores its prior Docker context. Failed/historical attempts retain
their own source. Report completion is required; sample count alone is not success.

Reports are capacity.json/html, soak.json/html and closeout-host.json/html, plus
current unit/deployment records. Current Linux unit evidence is closeout-units.json/html: 136 tests with zero
failures, errors or skips. The eight installed deployment and fourteen runtime
storage-fault regressions were also rerun after the resource window, so they did
not perturb those samples. The seven current report pairs bind one complete
62-file source manifest; older reboot/storage-boot reports retain their stage
source. The host digests match the finalized capacity and resource JSON. These are bounded controlled VM observations, not sudden
power-loss, boot zero-gap, external-client continuity or production-readiness
qualification. After closeout, feature scope stays frozen.
