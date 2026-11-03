The separate [explicit reopening stage](REOPENING.md) now consumes these closed

> Historical milestone: license status below describes that stage. The current
> project is [MIT licensed](../LICENSE); see [licensing scope](LICENSING.md).
proofs. This document describes the preparation stage only; it does not itself
authorize updates.

# Release preparation with fresh evidence, still closed

This milestone adds a root-only prepare-release operation. Success is
RELEASE_VERIFIED_CLOSED, not authorization: Gate stays VERIFIED_CLOSED, normal
admission/DEGRADED blocking remains in place, and no clean-stop receipt is issued.
There is no actual release/unlock API in this stage.

## Contract and two original deadlines

After a current-session opening intention succeeds, submit exactly:

```json
{"op":"prepare-release","request_id":"release-001","opening_request_id":"opening-001","opening_marker_digest":"<marker_digest from opening result>","gate_epoch":"<current closed epoch>","gate_revision":7,"timeout_seconds":10}
```

UID 0 is required. Caller cannot supply a certificate, key, generation, file path,
command, replacement source deadline or an old storage/TLS result. The referenced
opening must be completed, still unexpired, latest in the main journal and paired
with the current Gate/preparation/core/health/DEGRADED history. Its request digest,
original budget and full target are captured in the accepted release row.

The release gets its own persisted 1–10 second budget. Every relevant authorization
checks both budgets; socket/subprocess/wait contexts use the earlier expiry.
Neither stored budget is rewritten or rounded forward. A ten-second release does
not gain ten seconds if the source has only a fraction of that time left. If
fresh checks cannot finish, the operator needs a new explicit opening intention
and new release ID. Same-ID replay returns historical state without dispatch or
time extension; changed parameters conflict. Startup checks source expiry too
when classifying an unfinished operation as INTERRUPTED or EXPIRED.

The shared version-2 recovery catalog gains an additive kind with strict target
and source-budget schema. Maximum 16 permanent root rows, one live executor and
128 control pages remain unchanged; large records can reach the pager cap first.
No automatic history recycling, extra emergency space or new dependency is added.

## Formal fresh verification

The real root recovery executor inherits the lifetime lease and holds the formal
writer lock. It repeatedly verifies the fixed source/pair, original budgets and
Gate authority, then:

1. Rechecks main journal integrity/schema, current READY core, healthy state,
   exact preparation and opening marker, and complete DEGRADED row references.
2. Performs a new private filesystem create/write/file-fsync/rename/directory-fsync/
   cleanup probe, plus a synchronous reserved SQLite-row write/COMMIT.
3. Runs the formal OpenSSL certificate validator on the committed generation and
   requires active.conf to point exactly there. No version fallback is allowed.
4. Runs the formal confirmer: three consecutive new trusted TLS connections with
   the expected leaf, no session reuse and same-connection HTTP 200. It rechecks
   certificate bytes afterwards. No Nginx selection/reload is performed by release
   preparation; preceding recovery must already have restored the correct service.
5. Under the shared decision barrier, atomically writes the latest main-journal
   release_preparation receipt, checking source/authority and effective deadline
   after tentative SQL and before COMMIT.
6. Separately records root RELEASE_VERIFIED_CLOSED. Before root COMMIT, it checks
   the exact receipt/source again, repeats filesystem and reserved SQLite probes
   to detect tested faults introduced after the first probes, rechecks certificate
   identity and finally checks both original deadlines.

Core, health, terminal normal requests, prior opening/preparation records,
immutable generations and active pointer are not rewritten. Only reserved probe
data and the new release receipt/root operation change. Partial observations in
failure results are named observed_storage_verified/observed_tls_confirmed;
they are not a successful overall release preparation.

TLS is a sample, not continuous proof about every Nginx worker, existing connection,
external client or WAN. This does not qualify uninterrupted connections or zero
downtime. A future actual release must define its handoff, admissible state evolution
and remaining freshness requirements rather than changing Gate alone.

## Paired receipt and crash semantics

```
ACCEPTED -> RUNNING -> RELEASE_VERIFIED_CLOSED
                  \-> FAILED / EXPIRED
restart of unfinished work -> INTERRUPTED / EXPIRED (no replay)
```

The strict singleton receipt binds release ID/digest, complete target digest,
source opening ID/marker, closed Gate and newly checked certificate identity.
Unknown/malformed prior receipt layouts or values are refused, not erased.
A final root result must match the exact current receipt. A delayed old completion
cannot overwrite a newer receipt or Gate epoch.

The main journal and root catalog are separate databases, not one transaction.
The receipt may persist while final root completion fails, expires or is interrupted.
That is not paired success. Returned COMMIT errors are uncertain, not proof that
no write persisted. release_prepared_closed requires matching current receipt,
durable completed root result, unchanged live source/pair and *both* budgets still
valid, with a final deadline check after metadata validation. It is an observation,
never admission permission and not a promise through network response delivery.

Service restart changes Gate epoch before serving, never automatically resumes
this operation, and preserves both stored budgets/targets. An old executor keeps
the inherited lease and prevents takeover until it exits. A repaired disk does
not resurrect a prior authorization. Completed results remain historical after
expiry/restart. The shared entry/executor/bound-COMMIT guard still blocks recovery
history and owned preparation/opening/release markers even under a RUNNING label.

Interrupted or failed probe artifacts may be retained as uncertain; this stage
adds no speculative cleanup/retry of those production artifacts. VM fixture cleanup
is separate and owns the entire temporary filesystem.

## Reproduce and evidence scope

Use the isolated Linux VM prerequisites in STORAGE_VERIFICATION.md:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 420 python3 tools/release_vm.py
```

[Release JSON](../evidence/release-preparation.json) and
[HTML](../evidence/release-preparation.html) run actual source service/root executor,
SQLite, OpenSSL, Nginx and fresh TLS, not a fixture backend. Every scenario first
creates a real activation SQLITE_FULL failure, then explicit certificate recovery,
journal preparation and opening intention. The repaired fixture pager allowance
adds eight pages for the new metadata tables; this does not make fault cases pass
by increasing capacity after the tested fault is injected.

The matrix uses actual ENOSPC on a dedicated virtual ext4 filesystem, read-only
bind/remount EROFS, and real SQLite pager FULL via large-allocation triggers.
It injects filesystem faults before fresh verification and after the receipt,
SQLite FULL at initial probe, receipt insertion and root completion. It also
checks untrusted CA rejection, independently observed wrong live leaf/HTTP 503,
source and own expiry, crash before/after receipt and at root publication, stale
Gate/source/receipt, malformed receipt and restart after completion.

Root-only fault hooks and offline fixture edits are not request options. Root
catalog FULL uses an extra pressure table/trigger which the fixture removes as
fault repair before restarting; it does not erase operation/source history.
The receipt-insertion FULL case seeds a structurally valid fixture receipt before
adding its INSERT trigger; that seeded row is not a completed prior release.
The test requires it to remain unchanged and never qualify as paired success.
Pre-crash pending rows and receipts are read before SIGKILL, excluding shutdown
cleanup as the recovery explanation. No real VM reboot is part of this matrix.

[Unit JSON](../evidence/release-units.json) and
[HTML](../evidence/release-units.html) exercise real SQL/deadline contracts. Their
crypto calls are explicit mocks around fixture ledger data; they do not establish
certificate/TLS correctness. The VM matrix exercises the formal validator/confirmer.
Opening, preparation, certificate, storage verification, gate and storage regressions
are separately rerun against the same source. Prior unit records are historical.

Reports require a complete run, zero exit, unchanged source hashes, exact JSON/HTML
and successful owned process/mount/loop cleanup. Historical attempts retain their
own sources/results. Elapsed time includes all fixture provisioning and cleanup;
shared RSS fields sample the preceding activation/storage setup, not release peak,
total Nginx/VM memory or a comparative benchmark.

## Current validation

At that milestone the source passed 96 Linux unit tests with no failures/errors/skips and 26 release
VM fixtures. Separate opening (20, with its expected-failure mutation control),
preparation (19), certificate (17), storage-verification (15), gate (10) and storage
(14) matrices are regressions, not additional release scenarios. release-units.json/html
records that stage; current units are admission-units.json/html in REOPENING.md.

## Still unqualified

Actual admission release and successful normal updates after recovery are not
implemented. Installed package/systemd lifecycle, real VM reboot, abrupt power loss,
physical-media faults, arbitrary returned-COMMIT/fsync I/O errors, D-state cleanup,
continuous health and zero downtime remain unqualified. The tested storage faults
are specific virtual-FS/pager injection points, not every storage-failure timing.
Deadlines are cooperative authorization checks, not hard realtime completion bounds
for blocked kernel calls. Linux process evidence is not macOS runtime qualification.
GitHub remains Private and no license is selected.
