# Durable root storage/journal verification (P0-1 / P0-2)

> Historical milestone: license status below describes that stage. The current
> project is [MIT licensed](../LICENSE); see [licensing scope](LICENSING.md).

**Certificate recovery update:** [CERTIFICATE_RECOVERY.md](CERTIFICATE_RECOVERY.md)
adds a distinct full recovery kind with explicit v1-to-v2 catalog migration.
Storage-only operations still never restore or unlock; the 59-unit/fifteen-case
counts below describe the preceding storage milestone. Current source results
are listed in CLOSED_PREPARATION.md; the storage-only contract below is unchanged.

## Delivered scope

This stage persists a root verification request and tests storage plus journal
consistency. It **does not** select/reload a certificate, confirm TLS as a recovery
step, reset STORAGE_FAILED, reconcile normal activation outcomes, or enable
updates. The gate remains VERIFY_REQUIRED (or RECOVERY_REQUIRED after restart).
STORAGE_VERIFIED is a historical operation result, not admission authority or a
certificate-validity guarantee. TLS observations in VM fixtures check absence of
unintended changes, not successful TLS restoration.

The formal service runs a separate `certweft.recovery_executor` with the same
inherited lifetime writer lease, verified frozen root configuration, process
inventory and bounded process timeout as the activation executor. It shares the
single coordinator guard: root preparation, another verifier and normal activation
cannot run concurrently. SO_PEERCRED UID 0 is required for all new recovery APIs.

## Fixed API and persistence

First query recovery-status, then prepare-recovery with current gate authority.
From VERIFY_REQUIRED, use exactly:

```json
{"op":"verify-storage","request_id":"inspect-001","gate_epoch":"<current>","gate_revision":7,"timeout_seconds":10}
{"op":"recovery-request-status","request_id":"inspect-001"}
```

Timeout is a required integer 1–10 seconds. The accepted request stores its digest,
original boot-scoped budget, gate epoch/revision, fixed core target and a generated
probe identity. Target capture happens before durable admission; pre-admission
socket/input time is not part of this budget. The budget then covers dispatch,
worker startup, validation/probes and final result authorization. BOOTTIME/wall
assumptions and cooperative rather than hard realtime semantics are the same as
[DEADLINES.md](DEADLINES.md). fsync/D-state completion is not hard bounded by it.

- Same accepted ID and parameters return the stored operation without dispatch.
  Different parameters under that ID return request_conflict. This remains true
  before/after completion and across process restart.
- New IDs require the current gate authority and VERIFY_REQUIRED; stale authority
  cannot start work. Replay of a prior ID is historical, not a new authorization.
- There is one live root operation and 16 permanent root history rows in a separate
  protected recovery.db. Its connections cap the pager at 128 pages (normally
  512 KiB at 4 KiB/page); this is not a total disk or rollback-journal quota.
- Normal 64-row activation history does not consume these logical slots. Both
  databases still share the store filesystem: physical ENOSPC/EROFS can prevent
  root admission/result recording. There is no independent durable failure domain
  or preallocated emergency disk reserve.
- Root history is never silently deleted/recycled. Existing malformed/missing
  control-history tables are rejected, not automatically recreated as empty.

`ok=true, created=true` acknowledges durable admission only. Completion is read
from recovery-request-status. Replay/status responses are explicitly historical;
updates_enabled and restored remain false. There is no unlock/force operation.

## Restart and expiry behavior

ACCEPTED -> RUNNING -> STORAGE_VERIFIED / FAILED / EXPIRED

After the old executor exits and the lifetime lease is acquired, startup records
an unfinished request as INTERRUPTED, or EXPIRED if its original budget is already
invalid. It never dispatches it again or replaces timing/target/probe identity.
A retained budget from another boot is invalid; actual VM reboot is not qualified
in this milestone. There is no automatic resume or retry of filesystem probes.
A fresh root attempt needs a fresh accepted ID and current prepared authority;
this does not rewrite the older request's outcome or deadline.

Final success checks original expiry and gate authority inside the control
transaction, both before the update and immediately before commit. A probe that
finishes after expiry does not earn STORAGE_VERIFIED. If its small dedicated
journal probe already committed, that does not turn a failed/expired operation
into successful verification or restore a certificate.

## What validation actually does

The verifier acquires the real writer lock, checks current gate authority and
requires its captured committed/core target to remain identical. It opens the
existing journal without CREATE and checks:

1. SQLite integrity_check(1), required real tables/columns, singleton core/health
   rows, known core state, committed digest and pointer ownership via Writer.read.
2. Bounded activation history, known request states, digest/ID shapes and versioned
   timing-record shape. Expired historical timings are allowed, not renewed.
3. A private generated probe directory: exclusive creation, 4 KiB file write and
   fsync, rename, directory fsync, exact owned-name check, unlink/rmdir and parent
   directory sync. Cleanup failure cannot return success.
4. A real synchronous FULL transaction updating the journal's reserved
   storage_probe row (64 bytes), followed by another journal/target check.

The reserved row is provisioned by normal metadata initialization. A quarantined
startup no longer runs that initializer on the main journal; it preserves missing
schema for diagnosis rather than silently migrating/fixing it. Older quarantined
stores without storage_probe require a future explicit migration/repair procedure.
Normal status now opens the existing journal read-only and never creates a missing
state table. This is not a general SQLite salvage tool or a validator of arbitrary
root-created SQL extensions.

Core state, activation requests, health flags, certificate generations and the
active pointer are not deliberately changed by verification. The reserved probe
row **is** changed on successful write testing, so a whole-journal hash need not
remain identical. A preexisting STORAGE_FAILED health flag stays latched even
when verification succeeds. Actual certificate chain/key/SAN/expiry checks and
reload/fresh recovery TLS belong to the next stage.

If probe creation finds an existing path, it refuses without deleting it. Failed
or interrupted probes are retained; startup does not guess ownership or clean
unknown artifacts. Sixteen permanent operations bound the number of generated
probe identities until a future controlled retirement process exists. No storage
repair, eviction or history recycling is implemented here.

## Real VM evidence

[JSON](../evidence/recovery-validation.json) and
[HTML](../evidence/recovery-validation.html) use the formal service/executor,
actual Nginx and dedicated ext4 loop filesystem in the isolated Linux VM. Cases
cover successful verification without unlock, replay/conflict/root authorization,
restart before/after original expiry, expiry while running and after the result SQL write but before final COMMIT,
unknown probe preservation, target/schema rejection, real filesystem ENOSPC and
read-only bind failure, actual SQLite pager FULL, and independent root capacity.

The FULL fixture uses a root allocation trigger on storage_probe plus a real
max_page_count limit; it does not fabricate SQLITE_FULL with RAISE(). Control
recording remains available under that main-journal quota. For physical-path
ENOSPC/EROFS, recording may be impossible: the service exits 75 and the durable
request remains unfinished/failed, never verified. The report establishes the
independently observed fault and safe refusal; it does not retain the exact
verifier syscall where an unrecordable filesystem fault surfaced. A separate success case keeps
prior STORAGE_FAILED unchanged. Normal-history capacity is root-fixture seeded
through formal Operations metadata methods alongside the fixture's real healthy
activation; it is not evidence of 64 successful rotations. Sixteen root requests
then run through the formal service; the next new ID is refused and old IDs remain
readable.

On SIGKILL, the fixture reads pending control state before restart, checks the old
verifier still fences takeover, then terminates it. Original timing/target/probe
remain unchanged and the inventory shows no replayed verifier. An interrupted
4 KiB probe is retained rather than re-executed or silently removed. Independent
protected-table hashes, pointer/version sets and fresh TLS observations check
that neither verification nor restart pretends to restore service. These are
process restarts with Nginx still running, not VM reboot or power-loss tests.

In a disposable Linux VM with the prerequisites in RESTART_GATE.md:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 240 python3 tools/recovery_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 180 python3 tools/gate_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 180 python3 tools/storage_vm.py
```

A nonzero exit, timeout, missing/in-progress report, changed source or failed
cleanup is not passing evidence. Prior attempts remain in recovery-attempts.
Development attempts include an overfilled normal-history fixture, a process
cleanup ESRCH race, and an early capacity assertion that omitted the API rejection
detail. The history setup now fills only the remaining slots to 64; cleanup treats
only ENOENT/ESRCH as exited, and the capacity sequence waits for the previous
coordinator to be idle before its next new request. Actual refusal reasons are
asserted rather than indexed as if every call succeeded. Those failed attempts
are retained, not counted as qualification. Elapsed fixture times/RSS snapshots
include provisioning and exclude total Nginx/VM memory; no recovery SLA or
comparative performance claim is made.

## Current validation

Current source passes 59 Linux unit tests
([JSON](../evidence/recovery-units.json), [HTML](../evidence/recovery-units.html)),
fifteen recovery-verification VM fixtures, ten restart-gate/lifecycle fixtures
and fourteen storage regressions. Each current report binds exact source hashes
and checks owned-process/mount cleanup. The final-expiry VM case pauses the real
verifier after its success SQL update; an independent SQLite reader still sees
RUNNING, and expiry must roll that transaction back rather than publish success.

## Independent review correction

An independent logic review found that a corrupted persistent budget of null
could reach the general deadline helper's intentional “no deadline” mode. Valid
API admission never generates null, but the control-record reader previously did
not reject it; that could wrongly finish STORAGE_VERIFIED after the original
expiry. The gate still stayed closed, so this was not an unlock bypass.

Control records now require a non-null exact versioned budget: typed integers,
Linux boot UUID, bounded timestamps, 1–10 seconds and an exact duration relation.
Authority shape is strict, and its fields plus timeout are reconstructed to match
the stored immutable parameter digest. Existing history is validated at startup;
malformed data is preserved and rejected, not converted into unlimited time or
silently repaired. This is structural validation, not authentication against a
trusted root coherently rewriting all metadata.

New units reject null, missing fields, booleans, out-of-range/inconsistent timing
and malformed authority. Expiry tests use simulated consistent clocks or a real
one-second budget rather than deliberately malformed timing records. The formal
VM adds a case that pauses before the first record read, injects budget=null,
waits past the originally admitted one-second expiry and resumes. It requires
exit 75, no probe or successful result, and a closed gate. The raw malformed row
remains ACCEPTED because it cannot safely be parsed/finished. This is controlled
metadata-corruption injection, not physical disk-corruption recovery proof.

The independent evidence review found current reports/source/JSON/HTML consistent;
its note about missing exact syscall attribution for unrecordable physical-path
faults is retained above. Reviewers' host clock substitutes are not counted as
Linux verification; current VM results come from the actual Linux service.

## Remaining boundary

Storage verification is a bounded observation, not permanent health or permission
to reuse the result after later changes. Full recovery must recheck current
storage/journal, choose the intended committed certificate, validate it, reload,
confirm fresh TLS and durably reconcile before any opening decision. That flow,
installed systemd deployment, VM reboot, abrupt power loss, physical-media/fsync
failure recovery, D-state cleanup and automatic rollover remain unqualified.
Repository stays Private; no license selected.
