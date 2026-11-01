# Explicit root reopening

This stage adds `open-updates` to the **source-run formal local service**. It is
not an installed systemd deployment. Only UID 0 may request reopening; a
controller UID may submit normal certificate updates only after the complete
opening pair is authorized.

## Contract and deadlines

```json
{
  "op": "open-updates",
  "request_id": "open-001",
  "release_request_id": "release-001",
  "release_receipt_digest": "<prepare-release result receipt_digest>",
  "gate_epoch": "<current closed gate epoch>",
  "gate_revision": 8,
  "timeout_seconds": 10
}
```

The object has exactly these fields. Bind the current `VERIFIED_CLOSED` Gate and
completed `prepare-release` receipt. The separate root recovery catalog retains
its **16 total permanent request rows**, shared by all recovery operation kinds;
normal activation retains its separate 64-row bound. There is no automatic
history recycling or emergency disk reserve.

A new request captures the release target/digest and original release budget.
Execution is capped by the earliest of three original deadlines: opening
intention, release preparation and this reopening operation. Same-ID/same-body
replays return history, without dispatch or new timing. Same-ID/different-body
requests conflict. Linux boot-time clocks plus boot ID fence rebooted timing;
wall-clock assumptions remain as documented in DEADLINES.md. A preparation that
has expired must not be refreshed by merely issuing a new reopening request.

On successful opening, the resulting admission grant lives only in this running
service session. The operation deadline is not a periodic renewal timer for an
already-open session. Fresh activation requests retain their own activation and
recovery deadlines.

## Verification and permission boundary

The inherited root executor takes the existing lifetime/writer locks. It checks
the exact source receipts, core/journal snapshot, HEALTHY state and immutable
references to every prior DEGRADED request. It performs a new filesystem
write/fsync/rename/directory-sync/cleanup probe, reserved SQLite write/COMMIT,
formal certificate validation and three **new** trusted TLS/HTTP-200 connections
to the committed leaf. A correct active symlink alone is insufficient.

Publication order:

1. Commit `admission_release` in the main journal. This is inert evidence.
2. Publish RUNNING Gate at the next revision under the decision barrier. This
   marker alone is also insufficient.
3. Commit `OPENED` plus the exact admission digest/new Gate in the root catalog.
   Before this commit, repeat writable storage checks and revalidate timing,
   source, journal, receipt and certificate identity.
4. The service validates the full pair and adopts that exact Gate authority
   before its next activation, with another original-deadline check. Old executor
   configurations retain the old token.

The formal entry, executor and bound activation COMMIT all call the shared
admission guard. It requires all three records to agree. Referenced terminal
DEGRADED rows are **not rewritten**: only their exact captured hashes are exempt
from blocking activation. Added, removed or changed DEGRADED history or a new
storage-health failure blocks permission. A final receipt by itself cannot
suppress later failures.

A final timing check also runs after root COMMIT. If that durable result exists
but adoption is delayed past expiry, admission closes: the immutable historical
row can still say OPENED while current `gate_allows_updates` is false. This
explicitly separates a committed root record from live session permission.

The filesystem and two SQLite databases do not form one atomic transaction.
Partial publication therefore remains non-authoritative. On a failed attempt,
only this attempt's still-current Gate may be demoted; a newer Gate is preserved.
If storage prevents recording failure, all fatal storage-result/latch paths
terminate and wait for the active executor before coordinator exit. The VM
explicitly keeps an executor SIGSTOPed while injecting EROFS and requires it to
be gone before storage repair. A transient takeover refusal was found during
validation: a direct fatal exit could leave the lease correctly held by an old
executor. The shared kill/wait failstop now covers those exits too; the fixture
never fixes this by silently killing an orphan after repair. Uninterruptible
process exit remains outside qualification. The coordinator does not claim
success. A main receipt can survive a failed root completion and is retained for
inspection; it is not permission.

## Restart and recovery

Startup rotates Gate authority before exposing the endpoint. Pending operations
become INTERRUPTED/EXPIRED without replay; original timing/targets stay intact.
A completed OPENED row is historical, and cannot authorize a new service session.
Reopened recovered stores are deliberately **closed again after service restart**,
including a normal stop/restart in this bounded slice. Repeat the root recovery,
reconciliation and fresh opening sequence to reopen; do not edit Gate/database
files manually. This is not an always-on operational deployment claim.

`recovery-request-status` and dedup replies are historical records. Use
`recovery-status.gate_allows_updates` for this service's current admission
snapshot; an old OPENED result does not mean the current session is open.

## Reproduction and evidence

In the disposable Linux VM with the prerequisites in REPRODUCE.md:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 420 python3 tools/admission_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The VM runner uses the real root service, inherited executor, SQLite, OpenSSL and
Nginx. It first induces a real activation SQLITE_FULL fault, then exercises the
complete closed recovery/preparation chain before reopening. Main pager capacity
is frozen at the original fixture limit plus 12 pages for this larger chain;
it is not enlarged after injecting a fault. FULL triggers attempt a 1 MiB
allocation exceeding that fixed cap; the root catalog keeps its 128-page cap.
The main-FULL case seeds an inert well-formed main record solely to install an
INSERT trigger; it is not a prior successful reopening.

The current matrix has 26 formal-service cases; the full Linux unit suite has
111 tests (including 15 new admission-boundary tests).

The matrix includes real ext4 ENOSPC, read-only bind-mount EROFS and SQLite FULL
at reserved-probe/main-publication/root-completion points; expiry, changed source
history, wrong wire leaf, HTTP 503, stale Gate/receipt and SIGKILL at publication
boundaries. Pending root state is read before killing the coordinator, and the
stopped inherited executor must prevent takeover until it exits. This is process
restart evidence, not VM reboot evidence.

Successful scenarios submit an actual new certificate through the unprivileged
controller path, require COMMITTED, and independently observe the different leaf
plus HTTP 200 on a fresh trusted connection. Replays must add no executors. The
reply-loss scenario closes the first admission connection before reading its
acceptance reply, then replays it while the executor is paused, and also loses a
completed dedup reply;
it does not simulate arbitrary network partitions or power loss.

Reports `evidence/admission.json` and `.html` contain the same results and source
hashes. Nonzero exit, timeout, incomplete report, failed cleanup or source change
is failure. Old attempts are archived, not counted as passing runs. Unit tests
exercise real SQLite/transactions but mock certificate check/confirm; they do
not substitute for the formal TLS VM cases.

Timing is elapsed fixture/reopening workflow observation (including deliberate
pauses, checks and follow-up activation where applicable), not a latency SLA or
hard realtime guarantee. RSS/HWM are separate snapshots of the VM service and
executor, not total VM/system memory, leak qualification or native-host results.
Checkpoint HWM is the high-water mark *so far*, not a complete executor-lifetime
peak. In restart scenarios, before/after service snapshots can refer to different
process instances and must not be subtracted as a growth measurement.

## Limits

No installed systemd lifecycle, VM reboot qualification for this reopening path,
sudden power loss, physical-media durability, arbitrary returned-COMMIT/fsync I/O
errors, uninterruptible D-state recovery, zero-downtime connection guarantee or
continuous TLS health qualification is claimed. SQLite FULL/ext4 path faults
exercise specific write boundaries, not every storage failure semantics.
The tested post-reopening activation uses the dedicated OpenSSL fixture CA;
Smallstep CSR authority remains separately qualified, not a newly integrated CA
renewal workflow. The project remains Private with no license selected.
