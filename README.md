# Certweft

A bounded single-host service for activating and recovering Nginx TLS certificates.
It validates a candidate, persists intent, reloads a fixed Nginx target and requires
three new trusted TLS connections with the intended leaf and HTTP 200 before
COMMIT. An abnormal writer restart closes admission; trusted root recovery is
explicit, persisted and checked before updates can reopen.

**Status:** Private, version 0.0.2, MIT licensed. Feature scope is frozen.
This is an isolated-VM evaluation MVP, not a production-readiness guarantee.

## What is implemented

- Same-key CSR reissuance through one restricted Smallstep CA, certificate policy
  checks and a separate credential-delivered signing account. This is **not**
  possession-only renewal; the tested serverAuth-only `step ca renew --mtls=false`
  route failed on the recorded Smallstep versions.
- Installed wheel/CLI and fixed systemd writer/Nginx/signer units; operator peer
  authorization, a root writer bounded to CAP_CHOWN and inherited executor fencing.
- Durable request deduplication, cancellation/COMMIT boundary, persisted deadlines
  and a separate recovery budget. A new TCP/TLS connection is used for confirmation.
- Closed startup after uncertain execution, root storage/journal checks, committed
  certificate restoration, reconciliation and paired explicit reopening.
- Finite history/generation bounds and safe refusal; normal VM poweroff/start and
  dedicated-state ENOSPC/read-only/SQLite FULL experiments with explicit repair.

## Evidence at the current source

The [results ledger](docs/RESULTS.md) and [closeout guide](docs/CLOSEOUT.md) bind
current JSON/HTML to the same 62-file implementation/test/tool manifest. Package
payloads are verified against the installed wheel; historical reports retain
their original source and are not counted as current reruns.
The subsequent MIT adoption changes packaging metadata and documentation only;
recorded manifests retain their pre-license pyproject.toml. Runtime/test/tool
bytes are unchanged; license packaging was verified separately.

| Qualification | Observed result |
| --- | --- |
| Linux unit tests | 136 passed; no failures, errors or skips |
| Independent capacity/remaining-root cases | 9 passed through installed services |
| Installed deployment regressions | 8 passed |
| Source-service runtime storage-fault regressions | 14 passed |
| Resource window | 1,200.182 seconds, 121 samples, no writer/master restart |
| Stable writer RSS / FD | 21,840–21,932 KiB / 5 |
| Stable Nginx summed cgroup RSS / FD | 13,432 KiB / 15 |

The resource experiment creates eight successful updates, two rollbacks and four
stale-core failures, then runs fixed-history queries/replays/rejections. It is a
modest control-plane workload, not continuous rotations or a saturation test.
After the 180-second warmup, worker identity and full history stay fixed; sampled
state disk usage is constant. RSS sums can double-count shared pages. These
single controlled VM observations are not native-macOS measurements, restoration
SLAs, complete lifetime peaks or evidence of long-term leak-free operation.

Separate [normal-reboot evidence](docs/REBOOT_VALIDATION.md) and
[storage-fault reboot evidence](docs/STORAGE_REBOOT.md) retain their stage-specific
manifests. Their three-case matrices were not silently relabeled as reruns at the
latest closeout source. Reviews and corrected false-pass controls are linked from
those guides and [the closeout review](docs/CLOSEOUT_REVIEW.md).

## Operational limits

The installed target is Ubuntu 24.04 ARM64, Python 3.12, systemd 255, Nginx 1.24,
Smallstep CLI 0.31.0 / CA 0.30.2, one fixed IPv4-loopback listener and DNS SAN
`localhost`, P-256 key and pinned trust root. Host root and the local systemd
manager are trusted. There is no remote management API, arbitrary unit selector,
production CA enrollment, automatic scheduler, key/trust rotation or multi-host
support. The installer creates a dedicated evaluation target; existing system
Nginx units/configurations remain outside its managed scope.

Normal history is capped at 64 requests, root history at 16 rows and immutable
generations at 16 directories. A new complete recovery uses five root rows with
**no whole-workflow reservation**: insufficient allowance can complete some steps
and then fail while remaining closed. There is no qualified GC, rollover/reset
or production-store migration. A recovered session closes again on later restart.

A candidate can remain online while management is closed or unavailable. ENOSPC
or read-only storage can prevent writing a new Gate; an old RUNNING file is not
live authorization. Storage repair/restart alone does not reopen uncertain state.
Boot zero-gap, sudden power loss, arbitrary media/fsync/COMMIT I/O failures,
external reachability and all-client connection continuity remain unqualified.
No hardware recovery or full-service availability guarantee is made.

## Start here

1. [Installation and operator/root CLI](docs/INSTALL.md): fixed paths, trust model,
   privilege boundaries and explicit repair/reopening.
2. [Current architecture](docs/ARCHITECTURE.md): coupled state, fencing and limits.
3. [Validation/reproduction index](docs/REPRODUCE.md): current commands versus
   historical source-run experiments.
4. [Capacity/resource results and exhaustion runbook](docs/CLOSEOUT.md).
5. [Pre-publication review](docs/PREPUBLIC_REVIEW.md): evidence and privacy scope,
   license status and remaining publication decisions.

Original exploration and incremental contracts remain under docs/ and evidence/.
Their earlier claims apply to their own stage; no keys, CA databases, raw logs,
VM images, wheels or personal working agreements are committed.

## License

Certweft code and documentation are licensed under the [MIT License](LICENSE).
External tools retain their own licenses; see [third-party scope](docs/LICENSING.md).
Repository visibility remains Private until a separate publication decision.
