# P0-3a: durable requests and cancellation/commit boundary

## Scope and API

This milestone wraps certificate **activation**, after a certificate has been
obtained. It does not yet put CA issuance, queue time and recovery under a
persistent end-to-end deadline. There is still one privileged executor at a time.
A background coordinator waits for it while the ingress loop can serve bounded
request-status and cancel transactions. This is not a priority-control SLA;
a slow local connection can delay the single ingress loop by its read timeout.

Normal local callers use:

- submit: exactly op, request_id, certificate (PEM bytes as JSON string), epoch,
  revision. A successful reply means durable admission, not activation success.
- request-status: op and request_id; returns the durable state and result.
- cancel: op and request_id; returns current durable state plus explicit
  cancel_accepted and cancel_complete booleans. A COMMITTED result sets both false;
  ok only means the API request was handled, never that cancellation succeeded. CANCEL_REQUESTED is
  acknowledgement only; it is not a claim that the process or publication stopped.

Request IDs are 1–64 ASCII letters/digits/underscore/hyphen, scoped to this store.
The immutable SHA-256 parameter digest includes certificate bytes, epoch and
revision. Different encodings/line endings are different parameters. Same ID and
parameters always return the same operation, including after restart; a different
digest returns request_conflict. There is no automatic retry or ID recycling.
The old synchronous activate route is disabled unless the trusted root fixture
configuration explicitly enables legacy_api; P0-2 regression fixtures use that
compatibility path. It is not the normal deduplicated contract.

## Durable state and atomic outcome

The root-only journal.db now contains both the formal state row and requests.
Each short metadata transaction uses synchronous FULL and BEGIN IMMEDIATE. Ingress
never changes the Nginx pointer or sends reload. SQLite serializes metadata writes
against the executor's final transaction; it does not authorize a second system
mutation executor. Store/journal ownership and permissions are checked before
metadata initialization. The inherited lifetime lease still excludes takeover.

ACCEPTED -> RUNNING -> COMMITTED

Cancellation changes a live request to CANCEL_REQUESTED. If the executor has not
begun, it becomes CANCELLED without activation. After activation begins, the
cooperative boundary checks and final commit check reject a pending cancellation;
formal recovery must restore/confirm the prior committed version before the
request can finish ROLLED_BACK. That label does not imply the candidate was never
published. Other execution errors may finish FAILED; recovery uncertainty finishes
DEGRADED. Failed writes never acknowledge cancellation or completion.

The **same SQLite transaction** verifies RUNNING, writes the new committed
state and records COMMITTED. If cancel commits first, the executor cannot commit
that request. If COMMIT wins first, cancel returns COMMITTED and does not claim
cancellation. There is no separate in-memory flag deciding this ordering.

Terminal results never change on replay or late cancel. COMMITTED is a historical
transaction result, not a promise of perpetual certificate validity or current
service health. Parent failure after
admission does not trigger re-execution: after acquiring the lease, startup
reconciles unfinished work through the formal recovery backend and records
INTERRUPTED/recovered/not-replayed. COMMITTED requests are preserved rather than
rolled back. This is process-restart evidence with Nginx still running; it is not
VM reboot or power-loss qualification.

## Limits and safe refusal

Only one live request is admitted, enforced by a partial unique SQLite index and
the coordinator guard. History has 64 permanent rows per store. Full history
rejects new IDs but still returns old matching IDs. No history pruning, new-store
handoff or automatic rollover is implemented here. Immutable generation capacity
remains 16, so it can reject work before history fills. No references are reclaimed.

An uncertain executor result is recorded DEGRADED and blocks further new IDs.
Controller submission never implicitly repairs a preexisting DEGRADED state.
Controlled repair/release of that condition belongs to P0-3b; operators must not
edit the journal to force progress. Storage failure during startup recovery keeps
the service unavailable rather than claiming reconciliation. Executor timeout
remains 20 seconds; persistent whole-operation deadlines, clock handling and
cancellation of the separate CA signing step are still pending.

## Verification

In the disposable Linux VM with the executor prerequisites and free loopback
port 19445:

```sh
python3 -m unittest discover -s tests -v
sudo timeout 180 python3 tools/operations_vm.py
sudo timeout 150 python3 tools/executor_vm.py
```

The normal controller in the new VM flow is nobody, using the actual UDS service,
real exec and Nginx. The root fixture can pause the executor after new TLS
confirmation; this test hook is not a caller API. Cases cover live replay/conflict,
cancel-before-commit, terminal replay across process restart, commit-before-cancel,
pending journal preserved across SIGKILL, cancellation write failure, and rejection of implicit DEGRADED repair. The last
case injects a root journal state and is not a real storage failure.
An independent fresh TLS probe observes the final leaf/HTTP result.

Unit tests also race two independent SQLite connections for 20 iterations and
verify only the two legal outcomes. This is bounded concurrency evidence, not
exhaustive scheduling coverage. A SQL trigger injects cancellation write failure
in unit and VM tests; it is **not** real ENOSPC/read-only storage evidence.

[JSON](../evidence/operations.json) and [HTML](../evidence/operations.html) share
source hashes and result data. Prior attempts remain separate. Source changes,
incomplete reports, failed cases, nonzero exit, timeout or cleanup failure are
not passing evidence. Private fixture keys/config/logs remain only in the VM.
Earlier P0-1 reports retain their old source-bound scope; the separate executor
report is rerun as a regression, not represented as a new installed deployment.
