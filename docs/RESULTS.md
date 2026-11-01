# Results and provenance

## Current closed opening-intention milestone

See [OPENING_INTENT.md](OPENING_INTENT.md) for persistent intentions, exact
Gate/journal/DEGRADED pairing and the shared admission guard. This stage never
releases updates. Previous unit records are historical; current unit evidence
is opening-units.json/html.

## Closed journal preparation milestone

See [CLOSED_PREPARATION.md](CLOSED_PREPARATION.md) for the additive preparation
contract, main/root paired evidence and limits. This stage reconciles live
requests and health while keeping all normal updates closed. The follow-up review
adds complete receipt-value validation and an explicit non-success assertion for
both storage-fault result paths; malformed receipts are preserved, not overwritten.

## Closed certificate recovery milestone

See [CERTIFICATE_RECOVERY.md](CERTIFICATE_RECOVERY.md) and its source-bound
JSON/HTML for committed restoration, fresh TLS and crash/expiry cases. All normal
admission stays closed. Storage, gate and journal verification regressions are
rerun against the same source; prior unit records retain their historical scope.
The review hardened negative VM cases to require the formal validator/confirmer
failure stage and expected error, rather than accepting any FAILED result.
Sanitized terminal results are retained; raw OpenSSL stderr is not published.

## Durable storage verification milestone

See [STORAGE_VERIFICATION.md](STORAGE_VERIFICATION.md) and the source-bound recovery
validation/unit JSON and HTML. Gate and storage regressions are rerun separately.
No certificate restoration, health reset or unlock is claimed.

## Restart gate milestone

See [RESTART_GATE.md](RESTART_GATE.md), evidence/restart-gate.json and its HTML
for ten repaired-storage/lifecycle real-service gate fixtures. The older
47-unit record is historical; current unit counts are in STORAGE_VERIFICATION.md. Fourteen current storage regressions are separately source-bound.
No full restoration/unlock or VM reboot/power-loss claim is made.

## Previous reviewed storage milestone (historical)

See [STORAGE.md](STORAGE.md) and evidence/storage.json for fourteen actual-service
storage-fault cases. Faults are virtual ext4 ENOSPC, read-only bind path EROFS,
and SQLite pager FULL. Candidate TLS may remain live after filesystem-path write
failure; no successful rollback is claimed. Elapsed fixture times and sampled
process memory are not an availability SLA or a comparative benchmark.
That source passed 34 Linux unit tests and 47 VM cases across the storage,
deadline, operation and executor suites; see [historical validation](STORAGE.md#current-validation). earlier reports below retain their historical source hashes and scope.


## Earlier activation/recovery regression (historical)

The retained activation/recovery report passed 18 VM cases plus eight separately run
unittest tests. Elapsed workflow time was 16.67 seconds; Python driver peak
RSS was 33,892 KiB and private fixture logical size was 52,861 bytes. Source
unchanged and owned Nginx process cleanup checks passed. These measurements
are not comparable total-service benchmarks. The reviewed CSR authority milestone
has 14 CA/credential cases and nine separate unit tests; see CSR_AUTHORITY.md and evidence/policy.json.

## Original exploratory run (historical)

Final run: 15 listed VM cases passed in approximately 15 seconds. Three separate
unittest contract tests passed on Linux. This is not 18 distinct end-to-end cases.
Driver peak RSS was 28,408 KiB; logical private fixture data was 50,166 bytes.
These are one-run observations, not comparative performance or total service RSS.
JSON contains individual timings and exact source hashes.

Versions: Nginx 1.24.0 (Ubuntu), Smallstep CLI 0.31.0, step-ca 0.30.2,
Python 3.12.3, OpenSSL 3.0.13, Linux ARM64 VM. It runs actual processes directly
in the VM, not inside a container. No macOS runtime qualification is inferred.

The proposed token-renewal path did not work with a serverAuth-only leaf.
The first completed report records that failure. The final run reproduces the
incompatibility and separately verifies real same-key CSR reissuance. It must not
be described as proof that token renewal works. The CA fixture fixes the issued
SAN to localhost; production provisioner authorization is not qualified.

A subsequent report assertion incorrectly required DEGRADED when the Nginx master
was SIGSTOPped. Existing workers continued serving the previous committed leaf,
so actual rollback confirmation passed. The corrected test still requires
candidate activation to fail, the previous committed identity to remain, and
recovery after SIGCONT to succeed. The failed report is retained, not removed.

All four exploration areas have bounded observations, but the operational MVP
is not qualified. See ARCHITECTURE.md for explicit remaining gates. In particular,
the delayed-executor case tests a real forked lock holder, not an orphaned
privileged exec helper. SQLite FULL is tested at the journal save boundary,
not during a complete activation commit. Read-only is a real VM bind mount;
physical ENOSPC and fsync failure are not tested. No power-loss claim is made.
