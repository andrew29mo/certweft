# Current storage-fault reboot stage

[STORAGE_REBOOT.md](STORAGE_REBOOT.md) covers three installed-service fault/reboot/
repair cases with paired host evidence. All preserve the preboot journals and
uncommitted candidate; ENOSPC and read-only storage leave management unavailable,
while SQLite FULL leaves management closed and the formal root storage verifier
fails without restoration. After repair, explicit root recovery is still required;
old pending work becomes INTERRUPTED, old core authority is refused and fresh
core authority really activates the same candidate with the exact expected leaf.

Current results: **126 Linux tests** with zero failures/errors/skips; three
installed storage-fault VM reboot/repair cases; eight installed deployment
regressions; and 14 source-service runtime storage-fault scenarios all passed.
The six current JSON/HTML pairs are storage-reboot, storage-reboot-host,
storage-reboot-units, boot-bootstrap, deployment and storage. All bind the same
59-file source manifest; bootstrap overlaps deployment and is not counted as an
independent performance trial. Old reboot-stage reports retain their recorded
source. Host post-SSH check/repair observations were 3.667 / 3.882 / 3.921 seconds,
not boot time or recovery guarantees. Writer samples after repair were
21,656 / 21,648 / 21,660 KiB, not a stability or cross-mode memory comparison.

The current source includes 59 manifest files. No application module, packaged
unit, privilege allowance or license changes were made. The harness explicitly
closes SQLite read connections; the new descriptor regression checks this without
relying on garbage collection. The initial busy-mount attempt and later one-shot
observer dependency failure remain failed records, not passing reboot evidence.
Capacity closeout, bounded sustained operation, power loss, boot zero-gap and
arbitrary media/EIO failures remain unqualified.

# Earlier preserved-state VM reboot stage

See [REBOOT_VALIDATION.md](REBOOT_VALIDATION.md) for boot enablement, the exact
preserved-state contract, root recovery and limits. At that stage Linux unit evidence
was reboot-units.json/html: **125 tests, no failures/errors/skips**. Three actual
normal guest poweroff/start cases passed (pending, committed, reopened), alongside
four installed bootstrap cases. The eight installed deployment cases were also
rerun. These fixtures overlap; their counts are not independent workload trials.
The five then-current report pairs (reboot, reboot-host, reboot-units, boot-bootstrap,
deployment)
bind the same complete 57-file source manifest. The three installed fixtures also
verify package payloads against the wheel and source.
The earlier 148 source-run regression scenarios below were not rerun for this
harness/documentation-only stage and retain their historical source manifests.
No application module, unit template, privilege allowance or license changed.

All three reboot cases preserve the old main/recovery journals, Gate and active
pointer before writer startup. Gate remains closed, explicit root recovery
restores/verifies committed TLS, and stale core authority fails after reopening.
In the pending case a candidate remains online until that explicit recovery.
This is not automatic rollback on boot. Each old-CAS rejection is now paired with
an actual COMMITTED fresh-CAS activation of the same valid candidate and exact
new TLS leaf. Host Stopped/Running and boot IDs match the VM evidence; each boot
also verifies live installed writer identity. Measured check/recovery/control
sequences were 3.097 / 3.244 / 3.233 seconds after SSH was available, not machine
boot time or an SLA. Writer RSS after controls was 22,468 / 22,480 / 22,496 KiB
inside the VM, not a sustained-memory qualification.
Power loss, boot zero-gap and storage-fault-across-reboot remain untested.

# Earlier installed deployment milestone

See [INSTALL.md](INSTALL.md) and [DEPLOYMENT_VALIDATION.md](DEPLOYMENT_VALIDATION.md)
for the installed wheel/CLI/systemd scope, real Smallstep credential delivery,
process takeover, measurement limits and remaining gates. That milestone’s unit evidence
is deployment-units.json/html; older unit reports retain their historical source.
Earlier sections below describe their own milestones.

At that milestone fixed-source validation passed 120 Linux unit tests, eight installed
wheel/systemd scenarios and 148 source-run VM regression scenarios (156 regular
VM scenarios total). The ten then-current JSON/HTML pairs have identical payloads and
complete matching 54-file source manifests, including package resources and
pyproject.toml. Installed payload hashes also match those same source bytes.
Expected-failure mutation controls are separate and are not counted as additional
passing VM scenarios. The installed package version is 0.0.2.

# Earlier explicit reopening stage

See [REOPENING.md](REOPENING.md) for root contract, three-record admission,
original deadline intersection, failure/restart closure and real follow-up TLS
activation. Earlier closed milestones below retain their narrower stage scope.
At the reopening stage unit evidence was admission-units.json/html (113 Linux tests). The new
reopening matrix has 27 formal-service VM cases, including real follow-up
activation and fatal-exit executor cleanup. Earlier unit reports are historical.

The prior reopening-stage fixed-source validation was: 113 Linux unit tests, 27 reopening VM cases and
121 VM regressions (release 26, opening 20, reconciliation 19, certificate 17,
storage verification 15, gate 10, storage faults 14). The opening readiness
mutation and four new admission/cleanup controls are separate expected-failure
controls, not additional passing scenarios. See REOPENING_REVIEW.md for findings
and the distinctions between SQL, real-process and formal-service tests.
At that stage the nine JSON/HTML pairs have identical rendered payloads, exact current
source hashes and passing cleanup checks. No earlier failed/source-changed
attempt is counted; archived attempts remain available. This is bounded isolated
Linux VM/process evidence, not installed deployment or machine-reboot qualification.

# Results and provenance

## Earlier closed release-preparation milestone

See [RELEASE_PREPARATION.md](RELEASE_PREPARATION.md) for the source/release deadline
intersection, fresh verification, paired receipt and actual storage-fault points.
That preparation operation remains closed; the separate reopening stage above
can grant admission. release-units/opening-units retain their historical sources.

## Closed opening-intention milestone

See [OPENING_INTENT.md](OPENING_INTENT.md) for persistent intentions, exact
Gate/journal/DEGRADED pairing and the shared admission guard. This stage never
releases updates. opening-units.json/html is the historical unit record for
that stage. The follow-up review adds a final original-budget
check to readiness, an exact crossing-response test and a formal-service mutation
control that must detect removal of that check.

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
