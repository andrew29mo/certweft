# Exploration results

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
