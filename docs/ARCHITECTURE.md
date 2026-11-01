# Reviewed architecture and exploration decisions

The initial exploration sections below are historical. Current additions are
listed in the P0 updates, including the storage contract at the end.

## Original exploration scope

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

## P0-3b-1 update

Activation budgets now start at durable admission and persist across replay and
process restart. Recovery gets one separately persisted five-second budget,
reused across interrupted attempts. See [DEADLINES.md](DEADLINES.md) for decision
semantics, clock assumptions, schema compatibility and remaining limitations.

## P0-3b-2 first-round update

[Storage failure contract](STORAGE.md) adds an independent durable storage-health
latch and fail-stop when even failure recording cannot persist. Fourteen real-service
VM cases cover ext4 ENOSPC, path-level read-only EROFS and actual SQLite pager FULL
at admission, preparation, confirmed publication and cancel boundaries. Required
recovery remains permitted; restored TLS does not clear the storage fault.
Controlled repair, installed systemd lifecycle and power-loss testing remain open.

The P0-3b-2 independent review adds a bounded decision barrier and active-executor
stop-before-release on unrecordable metadata faults. Persisted quarantine survives
restart; an unpersistable fault does not provide a post-repair restart gate.
That was the reviewed first-round gap; the restart-gate update below now closes
quarantine after repair, while full restoration/reopening remains unqualified.

## Restart gate / root preparation update

[RESTART_GATE.md](RESTART_GATE.md) replaces automatic startup recovery with
preexisting execution uncertainty and a conservative recovery-only mode. Root
preparation is CAS-bound and persists VERIFY_REQUIRED without TLS/journal repair
or unlock. The unpersistable-latch post-repair restart gap is now gated; actual
safe restoration/reopening remains a later milestone.

The restart-gate review now requires a matching clean-completion receipt: STOPPED
publication without successful primary directory sync is insufficient to reopen.
Active shutdown and primary-sync EIO injection are tested separately from actual
storage-media/power-loss behavior; the receipt-final-sync ambiguity is documented
in RESTART_GATE.md rather than claimed as a universal fault latch.

## Durable verification update

[STORAGE_VERIFICATION.md](STORAGE_VERIFICATION.md) adds a separate 16-row root
operation history with preserved budgets and fixed targets. A lease-fenced
verifier checks storage/journal and writes only its reserved probe row. It never
clears health, restores a certificate or opens the gate. Quarantined startup and
status do not create/migrate missing main-journal schema.

## Certificate restoration without reopening

[CERTIFICATE_RECOVERY.md](CERTIFICATE_RECOVERY.md) adds versioned full-recovery
requests sharing the fixed root quota. The formal backend restores only the
captured committed identity and confirms new TLS. A durable intermediate proof
and paired final closed marker/result distinguish incomplete publication. No
health reset, normal-request reconciliation or RUNNING transition is delivered.

## Closed journal preparation

The additive reconcile-closed operation binds current certificate completion,
gate token, core and logical journal snapshot. It performs fresh storage/TLS
checks, atomically reconciles live normal requests/core/health in the main
journal, then records separate closed root completion. Receipt plus current
root result are required for journal_prepared_closed; neither enables admission.
See [closed preparation contract](CLOSED_PREPARATION.md). Terminal DEGRADED
history is preserved; its admission policy and actual reopening remain pending.

## Opening assessment, no release

[OPENING_INTENT.md](OPENING_INTENT.md) adds an additive prepare-opening root kind
and a latest main-journal opening_intent marker. Marker/root publication is
paired and deadline-bound but does not change Gate or enable admission. Exact
DEGRADED row references are evaluated without rewriting terminal history. Shared
entry/executor/COMMIT eligibility permits untouched bootstrap only; recovered
sessions still require a future explicit release handoff.

## Closed release evidence

The additive prepare-release kind pins a completed opening marker/target and its
original budget, plus a new release budget. The earlier expiry bounds fresh
storage/certificate/TLS checks and separate main-receipt/root completion commits.
No Gate transition or DEGRADED-policy relaxation is included. See
[release preparation](RELEASE_PREPARATION.md) for tested fault points and limits.
