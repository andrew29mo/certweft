# P0-3b-1: persistent activation and independent recovery budgets

Current [opening-intention rules](OPENING_INTENT.md) add a shared admission guard
and refuse the old direct normal-executor recover-request route. The historical
automatic-recovery descriptions below are not current behavior.

**Startup-policy update:** [RESTART_GATE.md](RESTART_GATE.md) supersedes the
earlier automatic process-recovery/reopening descriptions below. Old report
counts and source hashes are historical. Current source validation uses the
gate and storage runners plus Linux unit tests.

## Fixed contract

The normal submit API optionally accepts timeout_seconds, an integer 1–10;
absence means 10 seconds. An explicit field is part of the parameter digest,
so changing it under an existing request ID is a conflict. Omitting the field
preserves the earlier digest format. The budget starts inside durable admission,
before INSERT/commit, and covers subsequent preparation, baseline validation,
staging, publication, reload, new TLS confirmation and COMMIT authorization.
Ingress bytes before admission and the separate CA signing step are not covered.

Each request stores a versioned activation record: boot ID, CLOCK_BOOTTIME start
and expiry nanoseconds, wall-clock reference and seconds. BOOTTIME includes suspend
on Linux. Replays return that original record; it is never recalculated. Metadata
reads and historical terminal results do not grant a new activation budget.

The executor enters the stored activation budget before preparation. OpenSSL
subprocess timeouts and TLS socket phases use the lesser of their existing limit
and remaining budget. Publication and reload signal boundaries check the budget.
The final SQLite transaction checks cancellation and the stored expiry before
writing state and again immediately before commit. Expired work cannot authorize
COMMITTED. This is a cooperative commit-decision deadline, **not** a hard realtime
bound on filesystem writes, fsync completion, scheduling or D-state cleanup. A
commit already authorized before expiry cannot safely be relabelled uncommitted
merely because storage completion is observed later.

An unstarted expired request becomes EXPIRED. If preparation expires before intent,
no publication occurs and no recovery budget is allocated. Once intent exists,
expiry invokes formal recovery; a successful recovery finishes ROLLED_BACK with
expired=true. ROLLED_BACK can also occur when intent existed but selection did not.
Failure to establish restoration finishes DEGRADED, never a false rollback claim.
Cancellation retains its existing ordering contract.

## Recovery and restart

The first recovery attempt persists a separate five-second recovery record before
changing the selected policy. It covers certificate checks, pointer selection,
nginx -t, pidfd reload, fresh TLS and READY recording. An existing recovery record
is reused, never renewed by process restart. Expired recovery records reject
further automatic restoration and record DEGRADED if possible. Recording failure
is permitted after budget expiry; this does not authorize a new policy change.

Process startup never resumes a pending activation. With the old executor gone
and lease acquired, it uses recover-request tied to the pending ID, preserving
activation and any recovery record. A remaining recovery budget may finish;
an exhausted one cannot be replaced. Existing core DEGRADED remains blocked.
Pre-deadline legacy pending records without timing are not resumed; they may
receive their first bounded recovery allocation. Historical terminal rows with
NULL timing remain historical and preserve their old parameter digests.

A different boot ID invalidates continuation of activation. First recovery after
a boot change may allocate a new recovery record only if none ever existed;
an existing record from another boot is rejected. Actual VM reboot behavior has
not been qualified here. Unit tests simulate boot-ID change. Wall-clock divergence
beyond five seconds from boot elapsed time rejects activation; same-boot recovery
also checks that reference. This detects jumps, not malicious or persistently wrong
system time. Certificate validity still depends on OS time. Actual NTP jumps,
clock trust and real suspend/resume are not VM-tested in this milestone.

## Reproduce and evidence

Use the executor VM prerequisites and free loopback port 19446:

```sh
python3 -m unittest discover -s tests -v
sudo timeout 180 python3 tools/deadline_vm.py
sudo timeout 180 python3 tools/operations_vm.py
sudo timeout 150 python3 tools/executor_vm.py
```

The deadline runner starts the actual service/executor and real Nginx. Its nine
cases cover replay/timeout-parameter conflict, expiry after candidate handshake and after both transactional SQL writes,
expiry before selection, delayed preparation, process restart before/after expiry,
and interrupted recovery with remaining/exhausted original budgets. Independent
fresh TLS observes restored baseline. Delay/stop checkpoints are root-only test
configuration, not a caller operation or real slow CA incident. The runner does
not alter VM clock or boot the VM. The final exhausted-budget case deliberately
leaves core DEGRADED rather than asserting successful restoration.

[JSON](../evidence/deadlines.json) and [HTML](../evidence/deadlines.html) share a
source-bound result. Private fixtures, timing boot IDs and raw logs stay in the VM;
public reports summarize invariants rather than exporting journal contents.
Failures, timeout, source changes and cleanup errors are not passing evidence.
Existing operation and executor regressions are rerun against this source.

## Still pending

First-round storage failure behavior is now covered in [STORAGE.md](STORAGE.md).
Controlled DEGRADED repair, durable whole-flow
CA signing integration, installed package/systemd lifecycle, actual VM reboot,
power loss and hard realtime behavior remain unqualified. History/generation
limits stay 64/16 without automatic recycling. No new rollback guarantee is made
when the old certificate is invalid or storage cannot persist the result.

## Independent P0-3b-1 review

Two read-only reviewers found no confirmed budget reset or expiry logic defect,
but identified a missing regression for the last COMMIT guard. A new SQLite
trigger/UDF test enters before expiry, delays the COMMITTED update across expiry,
and requires rollback of both state and request. This uses actual SQLite and
elapsed time, not physical storage failure. The setup transaction is committed
before opening a separate metadata reader to avoid a fixture-only self-lock.

The formal VM now pauses the executor after both SQL writes and before the final
check. An independent reader still sees durable APPLYING/RUNNING; after expiry,
resume must restore the baseline rather than commit. The root-only checkpoint
is not part of caller input. Confirmed/recovery checkpoints also independently
observe the candidate leaf before SIGKILL/rollback, and the before-expiry restart
case explicitly asserts its time premise.

The P0-3b-1 completed run had nine deadline VM cases and 26 separate unit tests, plus
12 operation and 12 executor regression cases. A targeted isolated-copy mutant
removing only the final expiry guard is detected by the new unit test:
[mutation result](../evidence/deadline-guard-mutation.json). Original source stays
unchanged. This is one targeted mutation, not broad mutation coverage.

Actual VM reboot, wall-clock jumps, suspend, fsync hard deadlines and power loss
remain unqualified. The unit boot/clock simulations do not change that boundary.
