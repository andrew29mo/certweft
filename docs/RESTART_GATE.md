# P0-1 / P0-2: preexisting restart gate and root recovery preparation

**Closed certificate completion:** [CERTIFICATE_RECOVERY.md](CERTIFICATE_RECOVERY.md)
adds VERIFIED_CLOSED without admission authority; restart still quarantines it.

**Storage-verification update:** [STORAGE_VERIFICATION.md](STORAGE_VERIFICATION.md)
adds durable root verification after preparation, without restoration or unlock.
Current unit counts and source-bound reports are listed there; the original
47-unit qualification below belongs to the preceding gate revision.

## Delivered boundary

This milestone implements restart quarantine and the **preparation contract** for
future safe recovery. It does not restore TLS, clear storage health, finish an
interrupted request, or reopen a quarantined store. There is intentionally no
unlock/force/reset operation. The running source service is not yet an installed
systemd deployment.

Previously, an unwritable journal could prevent STORAGE_FAILED from being
recorded. Restoring storage and restarting could then admit updates from stale
HEALTHY metadata. The service now durably marks execution uncertainty **before**
initializing metadata or binding its socket. The record exists before later
storage faults, rather than relying on another write after a fault.

## Durable record and startup

`execution.json` lives in the protected store. The service checks its regular-file
shape, effective-owner identity, private permissions, bounded size and exact
versioned schema; symlinks, corrupt or unknown records are rejected. File contents
are fsynced, atomically replaced, and the parent directory fsynced. STOPPED alone
is no longer clean authority. A separate private `execution-clean.json` receipt
must match the exact epoch/revision and canonical record SHA-256. It is issued
only after the primary STOPPED record's file and directory sync both succeed;
during service shutdown, primary write and receipt issuance occur under the same
decision barrier. An old
receipt cannot certify a newly replaced STOPPED record. Receipt reads are bounded,
regular-file/owner/permission checked and use NOFOLLOW. A failed start
write is not a successful startup. Root and the underlying storage stack remain
trusted; this is not protection against root deleting or forging the record.

A newly initialized backend provisions STOPPED and its matching receipt after
persisting its first committed baseline. Older stores with STOPPED but no receipt
are conservatively quarantined; no automatic enrollment or unlock is provided. The lifetime writer lease is acquired **before** any startup
record transition, so another writer or a still-living inherited-lease executor
cannot rotate the gate. Startup also uses the bounded metadata decision lock.

| Previous record | Startup result | Updates |
|---|---|---|
| STOPPED with matching clean receipt, followed by no pending requests | RUNNING, fresh epoch / incremented revision | Gate permits them; normal storage, core, history and authority checks still apply |
| STOPPED without matching receipt | RECOVERY_REQUIRED | Rejected, including partial clean-stop publication |
| RUNNING after abnormal exit | RECOVERY_REQUIRED, fresh epoch / incremented revision | Rejected, even if journal health says HEALTHY |
| RECOVERY_REQUIRED or VERIFY_REQUIRED | RECOVERY_REQUIRED with fresh authority | Rejected |
| Missing record on an existing/legacy store | RECOVERY_REQUIRED | Rejected; absence is not proof of a clean shutdown |
| Corrupt, unsafe permissions, unknown schema or record write failure | Startup fails | No new endpoint opened |

A supposedly clean session with pending work is also quarantined. Startup no
longer automatically restores a pending activation. It preserves the journal,
active pointer and live TLS identity for the later recovery verifier. That is an
intentional conservative change from the older restart reports.

An idle SIGTERM/SIGINT closes admission and may certify STOPPED only if there is no
active executor/coordinator, no live or DEGRADED request, healthy durable storage
metadata and READY core state. Interrupting active work kills/waits the executor
and leaves uncertainty recorded. A blocked/prepared session is never made clean
by terminating it. A replaced but uncertified STOPPED is not repair authority.
These are process lifecycle observations, not power-loss durability guarantees.

## Fixed local API

The normal UDS owner/controller still uses submit, request-status and cancel.
`status` adds the top-level `admission_gate` state, distinct from the core READY
state. Matching request replay remains historical and does not run work again.
New submissions require RUNNING. The formal executor independently checks its
frozen gate authority, and the final SQLite COMMIT checks it both before SQL
writes and immediately before commit, under the decision barrier. Necessary
in-operation rollback is not blocked by these admission checks.

Only Linux SO_PEERCRED UID 0 can use:

```json
{"op":"recovery-status"}
{"op":"prepare-recovery","gate_epoch":"<from recovery-status>","gate_revision":7}
```

`recovery-status` reports the gate and whether the executor is busy. Its
`gate_allows_updates` field describes only the gate, not verified storage or TLS
health. `storage_health_not_verified=true` makes that distinction explicit.

`prepare-recovery` requires exactly those fields, valid types, a currently idle
service, current gate epoch/revision and RECOVERY_REQUIRED. It persists
VERIFY_REQUIRED and increments revision. The successful reply explicitly says
`prepared=true`, `updates_enabled=false`, `restored=false`. No journal/TLS changes
occur. Current authority must be queried again after a lost response; replaying
the old CAS is stale, not another successful preparation. Another restart rotates
the epoch and invalidates every former preparation token.

The old unbound root `recover` API is refused with use_prepare_recovery. Ordinary
callers, extra reset fields, stale tokens and busy requests are rejected. A root
operator cannot clear the gate through this API. Direct root filesystem edits or
calling private Python backend methods are outside the API security boundary.

## VM evidence and reproduction

[Restart-gate JSON](../evidence/restart-gate.json) and
[HTML](../evidence/restart-gate.html) contain ten real-service fixtures. The first five cover
ENOSPC before admission / after publication, read-only bind before admission /
after publication, and cancellation plus health-latch writes both hitting real
SQLite pager FULL. Each repairs only the owned fault mechanism, restarts the
formal service, and requires continued refusal even when raw health is HEALTHY.

Pointers and the complete generation-name set are saved before repaired startup,
then compared after both restarts and preparation. Independent journal hashes
are identical **after fault-mechanism repair**, across
startup, preparation and another blocked restart. This excludes startup secretly
completing rollback or clearing pending state. Fresh TLS and pointer checks retain
the prior observed leaf; post-publication candidates may remain online. Root-only
preparation, normal-controller denial, legacy recover rejection, stale/replayed
CAS and old CAS after another restart are exercised. Active-executor cases also
require busy rejection and a competing writer to exit 73 without changing the
record. Before-admission fixtures first complete a real normal activation, an
idle clean shutdown and a clean restart with a new epoch.

Four additional fixtures signal the service (SIGTERM and SIGINT) while its
executor is paused at preparing or confirmed checkpoints, require executor exit
and a non-STOPPED gate, then verify two blocked restarts. The fifth lifecycle fixture injects EIO after primary STOPPED replace, just before primary
directory sync, in an otherwise idle healthy service with no pending request.
It requires a visible but uncertified STOPPED, a nonzero stop result, and refusal
after removing the fault hook and restarting. The hook is root-only configuration
and records a sanitized marker outside the store. This is formal-service fault
injection, **not** observed physical fsync failure or power loss. All five
lifecycle fixtures also terminate an idle, healthy RECOVERY_REQUIRED service
with both signals without clearing quarantine.

Receipt publication has a separate boundary: if its final directory sync reports
failure after rename, a matching receipt can still be visible. It certifies a
primary STOPPED record that was already successfully synced before receipt
issuance. Do not generalize this milestone to “every shutdown fsync error latches
quarantine”; that claim is neither implemented nor established by the VM case.

[Storage regression JSON](../evidence/storage.json) /
[HTML](../evidence/storage.html) separately rerun fourteen storage-fault cases
under this gate contract. Older deadline/operation/executor VM reports retain
their old source and automatic-restart semantics; they are historical, not current
qualification. Their corresponding legacy VM scripts require that historical
checkout for full-suite reproduction. Current Linux units retain the backend
budget, cancellation/COMMIT, real pager failure and executor contract tests.

In the isolated Ubuntu ARM64 VM, use Python 3.12, OpenSSL 3, Nginx, root, runuser,
ext4 loop/mount tools and the prerequisites in [STORAGE.md](STORAGE.md):

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 180 python3 tools/gate_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 180 python3 tools/storage_vm.py
```

Nonzero exit, timeout, missing/in-progress report, source changes or failed cleanup
are not success. Each owned loop image is unmounted/detached and tracked processes
are checked before private fixture deletion. Earlier failed attempts remain under
evidence/gate-attempts. One runner initially required an attempted faulty restart
to exit; a gated service can correctly stay running while refusing updates. The
revised assertion still requires actual refusal and a closed gate, not merely a
running process. Elapsed times include provisioning/repair/cleanup; sampled RSS
excludes Nginx/VM and is not a service peak or benchmark.

## Earlier gate-review validation

The 7b7eb2a gate-review revision passed 47 Linux unit tests
([JSON](../evidence/gate-units.json), [HTML](../evidence/gate-units.html)), ten
restart-gate VM fixtures and fourteen storage regression fixtures. The gate/storage
reports are now rerun with the recovery-verification source; current unit counts
are in STORAGE_VERIFICATION.md. Reports require
exact source fingerprints and verified private-fixture cleanup. Unit coverage
includes a real SQLite transaction in which gate authority changes after both SQL
writes but before final COMMIT; neither the request nor core state may commit.
The fsync-error unit is an injected call failure, not physical-media fault proof.

## Not yet delivered

The next stage must verify writable storage/journal, intended committed identity,
certificate validity, reload and new TLS before any safe reopening. Storage-health
reset, terminal reconciliation and that reopening protocol are not implemented
or qualified here. Missing/corrupt-gate repair, installed systemd lifecycle, VM
reboot, abrupt power loss, D-state cleanup and boot zero-gap behavior remain
untested. Root tampering, physical-media durability and external WAN reachability
are not covered. Repository remains Private; no license selected.

## Independent review corrections

Two read-only reviews found a partial clean-stop publication bug and two evidence
gaps. Primary directory fsync could fail after STOPPED replace, yet old startup
trusted that record alone. The new matching receipt closes that specific window;
the unit test fails the second real fsync call and independently observes the
uncertified STOPPED before restart. The earlier fsync test covered only failure
before replace. Other new units require missing/mismatched receipts to stay closed
and enforce receipt permissions.

The old VM fixture saved pointer/version observations only after repaired startup,
so it could miss pointer changes without reload. Those snapshots now precede
startup and include the full generation set at every claimed boundary. Direct
active-executor and idle RECOVERY_REQUIRED shutdown cases fill previously missing
lifecycle coverage. Failed and earlier reports are retained with their own source
hashes; only current source-bound results qualify this revision.
