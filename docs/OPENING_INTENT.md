# Opening intentions, still closed

This stage persists and validates an intention to reopen updates. It does not
implement release, write RUNNING, issue a clean-stop receipt or change the normal
DEGRADED blocking policy. OPENING_VERIFIED_CLOSED is an assessment result, never
an admission grant.

## Root contract and capacity

After current-session certificate recovery and reconcile-closed completion:

```json
{"op":"prepare-opening","request_id":"opening-001","preparation_request_id":"prepare-001","receipt_digest":"<SHA-256 of canonical receipt>","core_epoch":"<current core epoch>","core_revision":3,"gate_epoch":"<current closed gate epoch>","gate_revision":7,"timeout_seconds":10}
```

All fields are mandatory and no extra paths/commands are accepted. The service
requires UID 0. The preparation ID and receipt digest must identify the current
paired JOURNAL_VERIFIED_CLOSED operation and main-journal receipt; core and Gate
authority must match. Receipt digests use the canonical sorted, compact JSON form
in certweft.reconciliation.digest, not the byte hash of a formatted JSON file.

The shared version-2 recovery catalog gains an additive operation kind. Existing
rows are unchanged and unknown kinds fail closed on older binaries. This shares
the existing maximum 16 permanent root-history rows, one live root executor and
128-page catalog cap. It creates no extra emergency quota or automatic recycling;
large records may reach the pager cap before all 16 slots are available.

The accepted row binds kind, all request parameters and the original Linux
BOOTTIME/boot-ID 1–10 second budget. It captures the logical journal hash and
exact hashes of referenced DEGRADED rows. Same-ID replay is historical and never
dispatches or extends time; a different body under the same ID is a conflict.

## Paired assessment

The formal inherited-lease executor takes the actual writer lock. At admission,
before main marker publication, after tentative SQL and before the final root
COMMIT, the common pairing logic checks:

- The Gate is VERIFIED_CLOSED with the exact bound epoch/revision.
- The main receipt has the strict existing schema and matches its root request
  digest, certificate reference and completed preparation result.
- Preparation completion records journal_reconciled, health_verified,
  main_committed and updates_enabled=false, with matching receipt/journal hashes.
- Current core equals the receipt's READY core, candidate is null, immutable
  committed bytes still match their digest, and health is HEALTHY with no detail.
- No live normal request remains. Current DEGRADED IDs exactly match the receipt's
  resolved list; each entire row is hashed into the captured target. Any new,
  missing or changed DEGRADED history invalidates the assessment. Other logical
  journal changes also invalidate the preparation hash.

Terminal history, core, health, the reconciliation receipt, certificate bytes,
active pointer and Nginx configuration are not changed by this stage. DEGRADED
references are assessed, not deleted, rewritten as success or globally ignored.
The normal admission policy still rejects such history. A future release must
explicitly interpret valid resolutions under its own authorization.

This is metadata/journal pairing verification. It deliberately does not perform
a new certificate issuance, Nginx reload, filesystem write probe or TLS health
qualification inside the opening operation. The preceding preparation supplies
its bounded evidence; an eventual actual release still needs fresh storage,
certificate and TLS checks. Assessment does not promise continuous health.

## Separate publication boundaries

```
ACCEPTED -> RUNNING -> OPENING_VERIFIED_CLOSED
                  \-> FAILED / EXPIRED
restart of unfinished work -> INTERRUPTED / EXPIRED (no replay)
```

A single private main-journal opening_intent row identifies the latest intention:
request/digest, target digest, preparation/receipt, core identity and closed Gate.
Its unknown schema or malformed values are refused instead of overwritten. A new
explicit intention can replace a known historical marker. A delayed old result
must still match its exact marker and target; it cannot overwrite a newer marker.

The marker and root completion are in different SQLite databases. Marker COMMIT
may precede a failed/expired root completion. Such a marker alone is never a
successful paired result. Returned COMMIT errors are treated as uncertain rather
than proof that no write persisted. Both databases remain closed throughout.

recovery-status.opening_intent_verified_closed is true only for the latest exact
marker, durable completed root result, current pair and unexpired original budget.
A completed root record remains historical after expiry, but the readiness flag
becomes false. Restart changes Gate epoch, preserves journal evidence, interrupts
unfinished root work and never replays or automatically releases an intention.
The old executor's inherited lease still fences takeover until it exits.

## Shared admission guard

The formal submit/legacy mutation entry, normal executor and bound normal COMMIT
checks use the same require_updates function. It first requires the exact RUNNING
Gate authority, then permits only the untouched bootstrap path: valid private
recovery catalog with no root-recovery history and no owned reconciliation or
opening marker. Missing/unreadable metadata fails closed.

Once recovery history or either owned marker exists, even a RUNNING label is
insufficient: opening_handoff_required rejects updates. No accepted or completed
opening intention satisfies that guard in this stage. A later release milestone
must implement the explicit paired handoff, not remove this check or treat
HEALTHY/READY as permission. Gate status reports actual guard eligibility, not
merely a RUNNING label. The old direct normal-executor recover-request route is
also refused; formal recovery uses the dedicated authorized recovery executor.

Raw Python library functions and a privileged actor editing root-owned state
are not a host-compromise security boundary. The supported service/executor
paths are the boundary tested here.

## Reproduction and evidence

With the prerequisites in STORAGE_VERIFICATION.md, in the isolated Linux VM:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 360 python3 tools/opening_vm.py
```

[Opening JSON](../evidence/opening-intent.json) and
[HTML](../evidence/opening-intent.html) run the real source service and executor,
actual SQLite, Nginx and preceding TLS recovery/preparation. They begin with a
real SQLITE_FULL activation failure and retained DEGRADED outcome. After fault
repair the frozen fixture pager limit gets four additional pages for the two
new metadata tables; this is explicit fixture capacity, not proof of success
under opening-phase disk exhaustion.

The matrix includes exact references, replay/conflicts, invalid receipt/core
binding, new/changed DEGRADED history, missing/mismatched receipts, incomplete
preparation, expiry before/after marker and at root COMMIT, completed-intention
expiry, three SIGKILL boundaries, two stale-Gate boundaries, a newer marker,
malformed marker preservation and restart after completion. It reads pending
control/marker state before kill, excluding a shutdown-cleanup explanation.
Main history/health and immutable files are compared independently throughout.

For adversarial admission checks, an explicit root fixture writes a RUNNING label
using the live service's own authority, then calls the real UDS entry and a separate
root-driven actual normal executor. Both must reject opening_handoff_required;
the bound production COMMIT guard must reject too. The fixture restores its own
Gate corruption afterwards. The separate direct-executor invocation passes a
matching fixture lease inode; it does not prove acquisition of the service's
exclusive lifetime lease. Actual inherited-lease fencing is tested separately by
the formal opening executor's crash/takeover scenarios. No mock backend substitutes
for these checks. Healthy-bootstrap regression remains covered by real normal
commits in the separate certificate matrix.

[Unit JSON](../evidence/opening-units.json) and
[HTML](../evidence/opening-units.html) cover SQL/authority contracts; their fixture
certificate/preparation proof records do not themselves establish TLS correctness.
Preceding preparation/certificate/storage-verification/gate/storage matrices are
rerun as regressions on the same source. Earlier unit reports retain historical
sources and scope rather than claiming current qualification.

Reports fail on nonzero exit, timeout, incomplete result, changed source or failed
owned cleanup. Elapsed fixture time is not an availability SLA. Shared RSS samples
come from the preceding activation/storage fixture, not an opening-stage peak,
comparative performance or total-service/VM memory measurement. Private keys,
configs and logs remain private VM fixtures, not report payloads.

## Current validation and retained failed attempt

The current source passes 85 Linux unit tests with no failures, errors or skips,
and 19 opening-intention VM fixtures. The 19 preparation, 17 certificate,
15 storage-verification, ten gate and fourteen storage fixtures are separate
regressions, not additional opening scenarios. The old 75-unit preparation record
is historical; current unit qualification is opening-units.json/html.

The first opening matrix attempt stopped in the shared fixture's second prepared
restart, before that case entered the new intention flow, with ConnectionRefusedError.
The previous readiness test relied on socket-file existence; that leaves a
bind/listen window and lacked a timeout failure branch. It now requires a successful
formal recovery-status reply, checks process liveness and has a bounded startup
timeout. New helper startup uses the same protocol-level criterion. The failed
attempt is retained in opening-attempts. This corrects an insufficient readiness
criterion; it does not prove a unique cause for the original transport failure or
relax any service-exit/non-success assertion.

## Not qualified

Actual reopening and successful updates after recovery are not implemented.
Installed systemd/package lifecycle, actual VM reboot, power loss, physical-media
failure, opening-phase ENOSPC/EROFS/FULL and general COMMIT/fsync I/O fault matrices,
D-state cleanup, continuous TLS health and zero downtime are not qualified.
Deadlines guard cooperative decision/COMMIT authorization, not a hard realtime
bound on a blocked kernel/fsync call. No macOS runtime claim follows from Linux
process tests. Repository stays Private, with no selected license.
