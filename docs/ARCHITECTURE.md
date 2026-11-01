# Reviewed architecture and exploration decisions

## Actual scope

One Linux host, one dedicated Nginx master/config/listener, one localhost DNS SAN,
P-256 keys, SHA-256 certificate signature policy, one Smallstep CA. No session
resumption during confirmation. No public management endpoint, arbitrary shell
API, certificate GC, automatic scheduling, installable daemon or privilege-separated
worker is delivered by this exploration.

Formal minimum code lives in certweft/core.py and certweft/ca.py. The runner imports
these modules and operates real Nginx and step-ca processes. Crash checkpoints are
explicit test hooks; real SIGKILL and SIGSTOP act on real processes. SQLite FULL
is a real SQLite max_page_count condition, not physical filesystem ENOSPC.
Read-only failure uses an actual bind mount remounted read-only in the VM.

## Fixed exploratory budgets

One flock-held operation, 16 immutable generation directories, 32 KiB certificate
input, 8-second command timeout (15 for CA signing), 5-second activation window
starting after candidate staging, separate 5-second recovery confirmation window,
2-second probe socket timeout, 4 KiB HTTP header budget. These are exploratory
limits, not an end-to-end deadline contract. Command capture is not yet byte-bounded.
Three consecutive confirmations are samples, not proof that all workers drained.

## State and authority

READY -> staging/validation -> durable APPLYING intent -> pointer replacement ->
nginx test/reload -> fresh wire confirmation -> durable READY with new committed
version. A publication intent includes the previous committed generation; files
are immutable and synced before selection. Configuration fragments contain
absolute paths into a single generation. Journal has schema, epoch, revision,
committed digest and candidate identity. Unknown pointers or committed content
drift are rejected before recovery writes. Host root is trusted.

Recovery of an incomplete operation selects and confirms the prior committed
version, then changes epoch/revision. Recovery of an already committed operation
reconfirms that committed version. Late old epoch/revision is rejected. A
separate process holding the real writer flock prevents takeover. This does not
yet prove inherited-FD privileged-helper fencing or systemd cgroup cleanup.

Rollback cannot be guaranteed on read-only/full storage. A live process attempts
DEGRADED recording if recovery fails; if that write also fails, durable outcome
remains unknown. Callers receive failure, never a successful rollback assertion.
No new operations are admitted from durable APPLYING/DEGRADED. There is no
trusted-root replacement or revocation lookup.

## Recovery matrix

| Boundary | Required behavior |
|---|---|
| Before intent | No active change; abandoned owned candidate may consume capacity |
| Intent/selection/reload/confirmation, before commit | Reconcile to previous committed version; only claim rollback after fresh verification and durable recording |
| Commit persisted | Reconfirm committed version, never automatically choose an older version |
| Unknown pointer, changed committed files or invalid schema | Refuse writes; retain files for operator diagnosis |
| Old certificate invalid or recovery cannot complete | Failure/DEGRADED; no availability promise |

## Exploration findings and remaining MVP gates

1. Server-only token renewal failed on the tested pair. Real same-key CSR
   reissuance works but changes the credential threat model. Before MVP, enforce
   and negatively test CA-side name/purpose policy and root-only credential delivery.
2. Real new TLS and same-connection HTTP confirmation work. Master SIGSTOP is a
   real counterexample to treating reload signal success as activation success.
   Missing-intermediate wire rejection, expired/not-yet-valid certificates and
   expiry during commit/rollback still require dedicated tests.
3. Four actual SIGKILL checkpoints recover the previous committed generation.
   Independent writer-lock exclusion and old authority rejection are observed.
   Delayed exec helper inheritance, parent-death handling and systemd lifecycle
   are not yet qualified.
4. Real SQLite FULL preserves old journal content; real read-only mount refuses
   activation and supports repair. Post-publication physical ENOSPC, directory
   fsync failures, journal corruption and expired rollback remain unqualified.

Final MVP admission requires durable deduplication, bounded outputs/history,
protected rollback references, whole-operation persisted deadlines, cancellation,
clock anomaly handling, strict journal schema validation, safe operator repair,
and an installable systemd service with tested privilege separation. These are
acceptance gates, not implemented capabilities. No VM reboot, abrupt power-loss,
zero-gap boot, long-term rotation or zero-downtime claim is made.

Review corrections and distinctions between real and injected faults are in [REVIEW.md](REVIEW.md).

## P0-1 update

CA-side rejection of forbidden names, EKU, public-key algorithms and requested
lifetimes, plus transient systemd credential delivery are now qualified by
[CSR_AUTHORITY.md](CSR_AUTHORITY.md) and its separate report. The original
exploration gates above are historical; persistent deployment, executor fencing,
whole-operation deadlines and recovery gates remain open. CSR authorization is
restricted to one service identity, not bound to one host or public key.

## P0-2 update

The source-run root writer and actual exec lifetime lease now have bounded
privilege and takeover evidence; see [EXECUTOR.md](EXECUTOR.md). Nginx reload
is signalled directly after master identity checks, removing the delayed reload
helper path. Durable operation contracts and installed systemd deployment remain
open; the earlier descriptions of unqualified executor inheritance are historical.

## P0-3a update

Persistent activation request IDs and parameter digests now share the formal
journal with atomic COMMIT results. Cancellation is a durable tentative state,
not an immediate stop claim. See [OPERATIONS.md](OPERATIONS.md) for state,
replay/restart behavior and the fixed 64-row history bound. P0-3b deadlines,
controlled repair and formal deployment remain open.
