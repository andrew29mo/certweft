# Certweft

Exploratory single-host Nginx certificate activation and recovery backend.
Private project; no license has been selected. This is a bounded evaluation release;
finite-capacity and 20-minute resource checks are qualified; long-term stability
and automatic history rollover remain unqualified.

[Capacity limits, bounded resource results and exhaustion runbook](docs/CLOSEOUT.md)
cover the final closeout; [review corrections](docs/CLOSEOUT_REVIEW.md) enforce
first-restart history retention and stable worker identity. Feature scope is frozen.

Current installed operation: [installation/CLI guide](docs/INSTALL.md) and
[systemd deployment evidence](docs/DEPLOYMENT_VALIDATION.md), plus
[preserved-state VM boot recovery](docs/REBOOT_VALIDATION.md) and its
[review corrections](docs/REBOOT_REVIEW.md).
[Storage faults across reboot and explicit repair](docs/STORAGE_REBOOT.md) cover
ENOSPC, read-only storage and SQLite FULL; unavailable management is distinguished
from a persisted closed Gate. [Review corrections](docs/STORAGE_REBOOT_REVIEW.md)
cover old-root retries, terminal histories and current-startup failure evidence.
Earlier source-run
milestones below retain their individual scope.

The minimum implementation validates a candidate, persists activation intent,
selects an immutable configuration fragment, tests/reloads a dedicated Nginx,
and requires three new TLS handshakes with the intended leaf fingerprint and
HTTP 200 on the same connection. Recovery uses the durable committed generation.

## Important discovery

The tested Smallstep CLI 0.31.0 / CA 0.30.2 pair rejects serverAuth-only
`step ca renew --mtls=false` with incompatible key usage. This route is **not
qualified**. The alternative real CA CSR reissuance path preserves the key and
requires provisioner credentials; it is not equivalent to possession-only renewal.
The fixture CA template fixes SAN to localhost. The CA authority milestone below separately tests a restricted provisioner and
credential delivery; full deployment remains a design gate before the MVP.

See [independent review and corrections](docs/REVIEW.md).

## CSR authority milestone

[CA-enforced CSR policy and credential delivery](docs/CSR_AUTHORITY.md) now has
real CA rejection and transient systemd signer evidence. This does not qualify
the persistent deployment or privileged executor. The older token-renewal finding
and exploration reports retain their recorded scope.

## Writer/executor milestone

[P0-2 writer boundary and takeover](docs/EXECUTOR.md) adds a fixed local Unix
socket service, root validation, inherited executor lease and real orphan-process
VM evidence. Installed systemd deployment is now covered by the separate current milestone;
this section describes the earlier source-run boundary.

## Durable activation requests

[P0-3a operation contract](docs/OPERATIONS.md) adds persistent request deduplication,
responsive request-status/cancel handling and an atomic cancellation/COMMIT
boundary. CA signing is still a separate step; activation deadlines are covered below.
Controlled DEGRADED repair and explicit reopening are covered by the later milestones below.

## Persistent deadlines

[P0-3b-1 deadline contract](docs/DEADLINES.md) persists activation timing and a
separate first-attempt recovery budget. Replays/restarts do not renew them.
Expiry blocks COMMIT authorization; exhausted recovery remains DEGRADED.
This covers activation, not CA signing or hard realtime storage completion.

## Storage failures

[P0-3b-2 storage contract](docs/STORAGE.md) exercises actual ext4 ENOSPC,
read-only bind-mount EROFS and SQLite pager FULL through the formal local service.
Failed persistence cannot acknowledge cancellation or falsely commit/restore.
A durable storage latch blocks new updates; if even that write fails, the service
stops accepting requests. A candidate may remain live on an unwritable store.
The restart gate below now quarantines abnormal exits even when the fault latch
could not be written. Safe restoration and explicit reopening are covered below; installed deployment is qualified separately below.

## Restart gate and recovery preparation

[Restart gate / root contract](docs/RESTART_GATE.md) persists execution uncertainty
before accepting work. Repairing storage and restarting leaves the service closed
to updates; UID-0 preparation is bound to gate epoch/revision and never unlocks or
claims TLS restoration. Abnormal restart no longer automatically restores pending
activations. A clean restart requires STOPPED plus a matching completion receipt;
partial STOPPED publication and missing legacy records remain quarantined.

## Durable storage verification

[Root storage/journal verification](docs/STORAGE_VERIFICATION.md) adds persistent
request IDs, original deadlines and fixed targets in a separate bounded recovery
history. Formal filesystem and SQLite write checks can record STORAGE_VERIFIED,
but never reset health, restore TLS or unlock. Restart interrupts rather than
replays unfinished verification; old timing is preserved.

## Committed certificate recovery

[Recovery to VERIFIED_CLOSED](docs/CERTIFICATE_RECOVERY.md) adds root-only durable
restoration of the current committed generation, real Nginx reload and fresh TLS
confirmation. A paired completion record distinguishes finished recovery from
partial publication. Normal updates remain blocked; health/request reconciliation
and reopening are separate later stages described below. Old storage-verification history stays separate.

## Evidence

[JSON](evidence/exploration.json) and [HTML](evidence/exploration.html) contain the
same result, timings and source fingerprints. A passing exploration means its
listed cases passed, including observing the token-renewal incompatibility;
it does not qualify all proposed MVP requirements. Previous completed reports
remain under evidence/attempts. Two runner defects were encountered during
exploration: unsupported CA authentication and JSON serialization of an empty
byte result. The latter run could not publish a complete report; it is not
counted as passing evidence.

See [architecture and remaining acceptance gates](docs/ARCHITECTURE.md) and
[reproduction](docs/REPRODUCE.md). No keys, CA databases or raw logs are uploaded.

Current gate/source validation is in [RESTART_GATE.md](docs/RESTART_GATE.md).
Earlier operation/deadline/executor reports retain their historical source and
restart semantics; they are not qualification for the current startup policy.

## Closed journal preparation

[Closed journal and health preparation](docs/CLOSED_PREPARATION.md) adds the
root-only reconcile-closed contract, fresh storage/certificate/TLS checks and
atomic main-journal reconciliation. Paired completion remains closed; it does
not reopen updates, rewrite terminal history or automatically resume after a
process restart. Installed deployment is qualified separately; VM reboot/power-loss qualification
remains pending.

## Closed opening intentions

[Opening intentions and shared admission guard](docs/OPENING_INTENT.md) bind a
persistent root intention to the current Gate, preparation receipt, core and exact
DEGRADED history. Partial publication, expiry and restart never grant updates.
The formal entry, executor and bound COMMIT guard still reject recovered sessions,
even with a RUNNING label alone. The explicit reopening stage below adds the required completion pair.

## Fresh release preparation, still closed

[Release preparation](docs/RELEASE_PREPARATION.md) adds a fixed root contract,
independent source/release deadlines, fresh filesystem/SQLite/certificate/TLS
verification and a paired closed receipt. Disk faults or partial publication do
not grant updates. The separate explicit admission handoff is described below.

## Explicit reopening and real follow-up activation

[Root reopening](docs/REOPENING.md) requires fresh storage/TLS verification and
matching main-journal, Gate and root completion records. Partial publication
does not authorize updates. Exact references resolve prior DEGRADED history
without rewriting it; new failures remain blocking. Formal VM scenarios reopen
and actually activate a different certificate through the controller path.
Service restart closes a recovered store again; there is no automatic replay.
Installed deployment is qualified separately; this path's VM reboot, power-loss
and arbitrary storage-I/O qualification remain pending. See the source-bound [JSON](evidence/admission.json)
and [HTML](evidence/admission.html), including fault/cleanup evidence and separate
VM process memory snapshots.

The [reopening review](docs/REOPENING_REVIEW.md) corrects a COMMIT-test false
positive and a root-diagnostic inventory failure cleanup gap, with targeted
negative controls and source-bound Linux evidence.

## Installed package and systemd lifecycle

Version 0.0.2 adds the fixed installer, operator CLI, isolated writer/executors and
a separate credential-delivered signer. Real installed services exercise normal
activation, SQLite FULL repair/reopening, SIGKILL takeover, old-lease exclusion
and bounded restart limiting. The wheel payload is verified independently of the
checkout. See [the installation guide](docs/INSTALL.md) and
[deployment results](evidence/deployment.json) / [HTML](evidence/deployment.html).
No automatic boot or VM reboot recovery claim is made.
