# Independent exploration review

Two read-only reviewers examined the actual backend, tests and raw reports.
The following corrections were required, not merely documentation changes:

- SQLite save errors roll back the open transaction before durable-state recovery.
  A real second-connection reader induces SQLITE_BUSY at COMMIT and proves the
  old state remains. A separate injected open-transaction commit failure exercises
  formal activate/rollback against real Nginx; it is labelled injected, not FULL.
- Incomplete HTTP headers are rejected, status/header syntax is bounded and checked,
  and successful confirmations and final validation must precede their deadline.
- The leaf EKU is exactly serverAuth; signature algorithm is checked specifically
  as ecdsa-with-SHA256, rather than searching arbitrary text for sha256. The curve field is anchored;
  a real P-384 certificate with a spoofing CN is rejected in a regression test.
- The token-renewal finding now requires both serverAuth-only EKU and the actual
  incompatible-key-usage CA error, recording a sanitized reason/return code.
  Generic command errors no longer establish that finding.
- SIGKILL tests report reaching the intended checkpoint through a pipe, require
  SIGKILL specifically, and inspect durable APPLYING state before recovery.
- Nginx master/workers are awaited on cleanup; cleanup failure invalidates passed.
- Both JSON and HTML start as in_progress/passed=false, archive prior reports, fingerprint
  code/tests before cases and reject source changes at completion. Missing tools
  no longer prevent final error reporting. Historical reports retain original scope.

A review rerun initially lacked Smallstep executables because /tmp was cleaned
on VM restart. That failed invocation left an in-progress report and was never
counted as passing. Tools were reinstalled in persistent VM /var/tmp. Another run
was invalidated by the source-change guard while corrections were underway.
Neither is usable as final qualification evidence.

The CSR path authenticates using a provisioner credential, not just the existing
leaf key. The fixture's fixed SAN template does not qualify production credential
isolation or CA-side authorization for arbitrary deployment. No general claim
that server-only token renewal is impossible is made; the finding concerns the
recorded CLI/CA version pair and fixture policy.

Remaining limits still apply: fork lock exclusion is not privileged orphan exec
fencing; FULL is a save boundary; read-only rejection occurs before publication;
no physical ENOSPC, expired rollback, missing-intermediate wire test, systemd
service, VM reboot recovery or power-loss qualification is claimed. The core is
an exploratory backend imported directly from source, not an installed daemon.
