# Closed journal and health preparation

> Historical milestone: license status below describes that stage. The current
> project is [MIT licensed](../LICENSE); see [licensing scope](LICENSING.md).

The next [opening-intention stage](OPENING_INTENT.md) assesses exact references
without opening updates. The 75-unit record below is historical after that stage;
current unit evidence is linked there. VM preparation regressions are rerun.

This milestone prepares a recovered journal for a future explicit admission
handoff. It never opens normal updates. A certificate-recovery result alone is
not sufficient: the main journal may still be APPLYING/DEGRADED, storage health
may be latched, and normal requests may remain unresolved.

## Fixed root contract

After recover-certificate has completed in the current service session, use its
request ID and the current VERIFIED_CLOSED gate token:

```json
{"op":"reconcile-closed","request_id":"prepare-001","certificate_request_id":"restore-001","gate_epoch":"<current epoch>","gate_revision":7,"timeout_seconds":10}
```

This exact body is accepted only for UID 0 on the formal local service socket.
There are no caller-supplied paths, commands, health values or generation choices.
The referenced request must be a durable completed recover-certificate operation
paired with this exact closed gate and the current committed identity/digest.
An intermediate certificate proof or a closed marker alone is insufficient.

The operation shares the existing 16 permanent root-history slots and one live
root executor, not an additional emergency allowance. The control schema remains
version 2 with an additive operation kind; old binaries reject unknown kinds
rather than silently running them. No history recycling or automatic rollover is
added. The main journal gains one bounded closed_reconciliation receipt row;
unknown receipt layouts or malformed values are rejected rather than overwritten.
Receipt validation covers bounded IDs/digests, gate authority, the complete READY
core, and the element types/counts/uniqueness of interrupted/degraded references;
this is schema validation, not cryptographic protection against a privileged attacker.

Request digest binds kind, certificate request ID, gate epoch/revision and original
1–10 second budget. Replays return historical records without dispatch; a changed
body under the same ID is a conflict. Admission also captures the core and a
logical hash of state, health and normal-request rows. Cancellation or another
change to that snapshot causes rejection instead of being silently overwritten.
The reserved storage probe is excluded from this logical hash.

## Formal execution and atomic main-journal boundary

The real recovery executor inherits the service lifetime lease and takes the
formal writer lock. No new Nginx selection or reload is performed here:

1. Check authority and the captured journal snapshot; perform fresh filesystem
   write/fsync/rename/cleanup and synchronous reserved SQLite-row write.
2. Validate the captured committed certificate with the formal validator. Require
   active.conf to point exactly to committed, then require three new trusted TLS
   connections with its leaf fingerprint and same-connection HTTP 200. Recheck
   the certificate after these observations.
3. Under the shared decision barrier, begin a main-journal transaction and
   revalidate authority, snapshot and pointer. Mark only live normal requests
   INTERRUPTED, preserving their IDs, digests and original timing. Their result
   explicitly says execution_outcome=unknown; this is not a cancellation success,
   a fabricated COMMITTED result, or proof that an earlier side effect never ran.
4. Atomically set core READY/candidate=null with a fresh core epoch and increased
   revision, set storage health HEALTHY, and write the reconciliation receipt.
   Check authority and original deadline after tentative SQL and before COMMIT.
5. Separately commit the root operation as JOURNAL_VERIFIED_CLOSED. Immediately
   before that commit, recheck main journal/receipt hashes, authority and deadline.

Existing terminal results, including DEGRADED, remain byte-for-byte unchanged.
The receipt records which DEGRADED IDs were considered, without rewriting their
historical outcomes. Changing the normal admission policy to interpret those
resolutions belongs to the separate explicit reopening milestone in REOPENING.md. A health reset is
not a global permission to ignore DEGRADED requests or the gate.

The process owns no release method: execution.json stays VERIFIED_CLOSED with the
same token. Normal submit and legacy mutation paths remain blocked. VM tests submit the
current core epoch/revision and require a gate rejection reason, so stale core
parameters cannot accidentally satisfy the closed-admission assertion. Isolated
shutdown does not certify a clean STOPPED record. No keys or immutable generation
bytes are rewritten, and the operation does not issue or renew certificates.

## Paired completion and crash recovery

```
ACCEPTED -> RUNNING -> JOURNAL_VERIFIED_CLOSED
                  \-> FAILED / EXPIRED
restart of unfinished work -> INTERRUPTED / EXPIRED (no automatic replay)
```

The main journal and recovery catalog are separate SQLite databases. Their writes
are not claimed to form one atomic transaction. Main-journal commit may succeed
before the root result is recorded. In that case the journal may already be
READY/HEALTHY, but recovery-status.journal_prepared_closed remains false. The gate
still blocks updates. A returned COMMIT error is uncertain; failure results do not
claim that the transaction definitely failed to persist.

journal_prepared_closed requires the current VERIFIED_CLOSED gate, matching durable
root completion, matching main receipt digest and unchanged logical journal hash.
The older completion_recorded field still describes the paired certificate
recovery marker; it is not journal preparation or admission permission.
Historical success is not current health evidence after a new session or journal
change. The TLS proof itself is a sampled observation, not continuous monitoring.

A service restart always re-isolates this session with a fresh gate epoch. Pending
root work becomes INTERRUPTED or EXPIRED with its original timing and target,
never resumed or replayed. Completed records remain historical, and any main
receipt remains available for inspection. Explicit fresh certificate recovery and
a new preparation request can verify a partially reconciled journal; old authority
cannot authorize that work. An old executor retaining the lifetime lease prevents
takeover until it exits, even when its parent is dead.

## Reproduce and evidence

Use the isolated Linux VM prerequisites in STORAGE_VERIFICATION.md:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 300 python3 tools/reconcile_vm.py
```

[Preparation JSON](../evidence/journal-preparation.json) and
[HTML](../evidence/journal-preparation.html) use the formal source-run service,
actual Nginx/OpenSSL/TLS, SQLite and a dedicated virtual ext4 filesystem. Root-only
pause/fault hooks are fixture configuration, not request fields. The matrix checks
successful preparation, existing STORAGE_FAILED health, terminal-history
preservation, dedup/conflicts, three expiry boundaries, two stale-authority
boundaries, snapshot/pointer/material drift, actual ENOSPC/EROFS/SQLite FULL,
three SIGKILL boundaries and restart after completion. Storage faults in this
new matrix are injected after admission and before fresh storage validation;
they do not qualify every final-COMMIT I/O fault. It reads pending control
and main-journal state before killing processes, then checks inherited-lease
fencing and no replay. One partial-main-commit case additionally completes a fresh
explicit recovery and preparation after restart.

[Unit JSON](../evidence/preparation-units.json) and
[HTML](../evidence/preparation-units.html) exercise SQL/authority contracts. Fixture
proof records in units are not substitutes for the actual TLS VM tests.
Certificate, storage-verification, gate and storage regressions are independently
rerun against the same source. Reports bind source hashes and fail on a nonzero
exit, timeout, incomplete run, changed source or failed owned cleanup. Older
attempts retain their own historical sources and results.

Timing includes fixture setup/cleanup. The shared fixture RSS fields sample the
service before its initial storage fault and the normal activation executor; they
are not preparation-stage peak measurements. They do not measure total Nginx/VM
peak memory, a throughput comparison or a recovery SLA. Fixture
keys, CA material, raw configs and logs remain in the private VM workspace and are
removed during owned cleanup. Published records contain sanitized reason codes,
fixture generation/fingerprint identifiers and hashes, not private material.

## Current validation

At this milestone the source passed 75 Linux unit tests with no failures, errors or skips,
and 19 closed journal-preparation VM fixtures. The separate certificate (17),
storage-verification (15), gate (10) and storage (14) matrices retain their own
scope and reports; they are regressions, not additional preparation scenarios.
The 66-unit certificate-stage record is historical rather than current-source
qualification. preparation-units.json/html records that stage; current unit
qualification is admission-units.json/html, described in REOPENING.md.

## Review findings and retained attempts

The first matrix attempt correctly failed owned cleanup: deliberately corrupted
certificate bytes also made the fixture's nginx quit command fail to parse its
configuration. The fixture now restores only its own injected bytes after the
rejection assertions and before owned shutdown. The failed attempt remains in
preparation-attempts; its orphaned dedicated Nginx was identity-checked, stopped
and its unmounted fixture directory removed.

A later attempt failed on EOF while the actual read-only service was exiting.
Transport EOF is not a passing result: the harness now waits for an observed
process exit and separately requires exit 75, closed restart and an unchanged
main journal. A pilot rerun of read-only/full and crash cases passed owned cleanup.
The complete source-bound matrix above is the qualification evidence, not those
partial pilots. Neither correction weakens rejection or cleanup requirements.

## Independent review corrections

The follow-up review found two P2 gaps. First, the original receipt reader checked
only top-level keys and a few container types, so an abnormal record with null IDs
and empty core/authority objects could be overwritten. It now validates every
field and list element, rejects inconsistent references and validates generated
records before writing. SQL tests retain the exact malformed record and unchanged
main journal on rejection. The added formal-service VM fixture injects a complete
but malformed receipt after admission and requires reconciliation_schema failure,
no health reset, no paired completion and continued Gate rejection. This is not
proof of protection against a root attacker or arbitrary physical corruption.

Second, the original read-only/ENOSPC fixture skipped an explicit terminal check
when the service directly returned a result. The prior observed runs used exit 75
and restart into INTERRUPTED; the finding did not demonstrate a backend success
under those faults. Both fault paths now require a non-success result and
journal_prepared_closed=false. Direct replies must be FAILED with the intended
storage-validation stage and actual errno; unrecordable results still require
observed exit 75 and a closed, non-successful restart. Gate-only assertions are
not substitutes for operation-result validation.

## Remaining limits

This preparation operation never reopens admission. The separate
[explicit reopening stage](REOPENING.md) now uses a paired handoff and exact
DEGRADED-history references; it does not rewrite terminal outcomes. Package/systemd lifecycle, actual
VM reboot, power loss, physical-media corruption, general COMMIT I/O/fsync failure
recovery, D-state cleanup and zero downtime remain unqualified. Linux process
restart evidence does not qualify macOS runtime or machine reboot. Budgets use
Linux BOOTTIME and boot identity; a different boot expires them, while a detected
wall/boot-clock discrepancy fails closed. This is cooperative deadline enforcement,
not a hard bound on a blocked kernel/fsync call.

The repository remains Private and no license is selected.
