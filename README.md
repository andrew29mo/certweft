# Certweft

Exploratory single-host Nginx certificate activation and recovery backend.
Private project; no license has been selected. This is not the operational MVP.

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
VM evidence. Formal systemd deployment and complete operation contracts remain
pending.

## Durable activation requests

[P0-3a operation contract](docs/OPERATIONS.md) adds persistent request deduplication,
responsive request-status/cancel handling and an atomic cancellation/COMMIT
boundary. CA signing is still a separate step; activation deadlines are covered below.
Controlled DEGRADED repair remains pending.

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
Controlled repair and persistent systemd deployment are still pending.

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
