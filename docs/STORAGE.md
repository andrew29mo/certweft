# P0-3b-2, first round: storage failures before and after publication

## Contract

The source-run `certweft.service` and its privileged executor now classify
SQLite FULL/READONLY/IOERR/CORRUPT/NOTADB/CANTOPEN and filesystem
ENOSPC/EROFS/EIO/EDQUOT as storage failures. The detailed fault coverage below
is narrower than this classification; unexercised error families are not qualified.
Only sanitized SQLite error names and errno numbers are returned, not exception
messages containing paths or certificate bytes.

A separate durable health row latches STORAGE_FAILED when writing remains possible.
New request IDs and final COMMIT authorization check this latch. Request replay
remains historical, not permission to execute again. Initialization does not clear
the latch. Restoring the previous certificate and READY core state does **not**
clear the storage fault. A failed activation is recorded DEGRADED even when its
previous TLS identity has been restored. Required bounded recovery is not blocked
by the latch: it can still attempt to restore the committed generation using its
original recovery budget.

If the failure prevents persisting the latch or result, the service exits 75.
The caller receives an error or an incomplete/closed connection, never an admission
or cancellation acknowledgement. An EOF is an unknown request outcome, not a
rollback success. A previously accepted request can remain durably RUNNING with
core APPLYING while Nginx still serves the candidate. Do not infer the live
certificate from the committed journal identity alone. No automatic repair or
rollback guarantee is made for an unwritable store.

Cancellation is accepted only after its transaction commits. If that write fails,
`cancel_accepted=true` is never returned. When a SQLite FULL cancellation failure
can be durably latched, that latch also prevents the already-running executor from
committing after it resumes. This does not promise that a nonacknowledged cancel
was durably accepted on a completely unwritable filesystem.

Writer SQLite connections are now closed explicitly on leaving the lifetime of
the writer lock, including exception paths, rather than waiting for garbage
collection. SQL transaction rollback behavior is preserved.

## Real VM matrix

[JSON](../evidence/storage.json) and [HTML](../evidence/storage.html) contain the
same result, source hashes, fault codes, durable state summaries, fresh TLS
observations and cleanup checks. Twelve cases cross three fault types with four
boundaries: admission, running preparation before intent/publication, after new
TLS confirmation before COMMIT, and cancellation at that same confirmed boundary.

| Fault | Actual mechanism | Before publication | After publication / cancel |
|---|---|---|---|
| ENOSPC | Fill a dedicated 32 MiB ext4 loop filesystem; independently require errno 28 on a new write | Baseline pointer and fresh TLS remain unchanged; no successful admission on failed insert | No COMMITTED/ROLLED_BACK claim; service stops accepting; candidate can remain live |
| EROFS | Read-only bind mount over that store; independently require errno 30 | Baseline remains live | No successful outcome or cancel acceptance; service exits 75; candidate can remain live |
| SQLITE_FULL | Root-configured max_page_count on formal metadata and executor write connections, SQL allocation trigger requires a 64 KiB pager allocation | No publication; durable STORAGE_FAILED when possible | Transaction rolls back; previous fresh TLS restored, request DEGRADED; new IDs blocked even after service restart |

The allocation trigger uses `zeroblob`, not `RAISE(ABORT)` or a fabricated error.
It forces the pager to hit a real quota at a chosen SQL boundary. The SQLite
post-publication trigger fires after the core state SQL write but before the
COMMITTED request update can finish; both remain uncommitted. The root-owned
`sqlite_max_pages` setting is a bounded pager quota, not a total filesystem budget,
and is not a request API parameter. An invalid quota or quota below database size
is refused. Dropping the allocation trigger or restarting the service is not a
supported health-repair procedure and does not clear STORAGE_FAILED.

EROFS is a real path-level read-only bind mount, **not** an ext4 error-induced
superblock remount. Existing writable descriptors remain attached to the old
mount. The service must still reject because fresh metadata/cancellation/recovery
connections see EROFS. A normal superblock remount-ro during an active writable
SQLite connection was refused by Linux; that attempt is retained as failed
fixture evidence rather than claimed coverage.

The runner uses the real root writer, inherited executor lease, configured
unprivileged controller UID, dedicated Nginx and fresh root-verified TLS + HTTP
200. OpenSSL creates short-lived fixture leaves for the existing activation path;
this round does not rerun CA signing or qualify a complete CA-to-activation flow.
Root-only pause checkpoints locate boundaries; they do not replace the backend.
Read-only journal inspection independently checks the old committed identity and
absence of a new request ID, without calling an alternate recovery implementation.

## Reproduction and measurement limits

In an isolated disposable Linux VM with Python 3.12, OpenSSL 3, Nginx, root,
`mkfs.ext4`, loop devices, mount/findmnt/mountpoint/losetup and runuser:

```sh
python3 -m unittest discover -s tests -v
sudo timeout 180 python3 tools/storage_vm.py
sudo timeout 180 python3 tools/deadline_vm.py
sudo timeout 180 python3 tools/operations_vm.py
sudo timeout 150 python3 tools/executor_vm.py
```

Every case owns its image, mount, random loopback listener and private fixture.
The runner verifies tracked executor identities, Nginx process exit, unmount and
loop detachment before deleting owned fixture files. It never fills or remounts
the VM root filesystem. On a forced outer timeout or killed runner, inspect owned
processes/mounts before reuse; an in-progress or missing final report is failure.
Prior reports, including failed cleanup/remount attempts, remain under
`evidence/storage-attempts/`. Early attempts exposed the unclosed writer connection;
a new regression also caught and corrected an unclosed setup connection in the
test itself. The final connection test keeps garbage collection disabled and
requires the actual backend connection to be closed. Failed tests are not counted
as passing evidence.

Elapsed seconds include fixture provisioning, fault setup, operation and cleanup;
they are **not** recovery latency or availability bounds. Service VmRSS/VmHWM
are snapshots before the fault; executor values are snapshots at the stopped
checkpoint. They exclude Nginx, VM overhead and unsampled processes, and are not
a total-service peak, a native-host comparison or a sustained-load benchmark.
This Linux-only runtime uses BOOTTIME/pidfd; the macOS system Python/LibreSSL run
fails platform requirements and is not claimed as passing validation.

## Current validation

The current source passed 31 Linux unit tests ([JSON](../evidence/storage-units.json),
[HTML](../evidence/storage-units.html)), twelve storage VM cases, nine deadline
cases, twelve operation cases and twelve executor cases. Each current report
checks source hashes and its own cleanup. Earlier CA and exploratory reports
remain historical and were not rerun as part of this storage milestone.

## Still open

Controlled DEGRADED repair and safe recovery after restoring storage are a later
milestone. So are persistent systemd deployment, VM reboot qualification, actual
power loss, filesystem/fsync corruption and hard realtime bounds. This round
exercises ENOSPC on a virtual ext4 image, EROFS on a bind path, and SQLite pager
FULL; it does not qualify physical-media loss, arbitrary IOERR/CORRUPT variants,
long-term rotation or automatic quota/history recycling. History/generations
remain bounded at 64/16. Private repository, no license selected.
