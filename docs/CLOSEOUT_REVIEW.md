# Capacity and bounded-resource review corrections

The review checked the original installed-service experiments, formal
implementation, raw series and report/documentation claims. It found validation
holes rather than demonstrated application corruption or an actual restart in
the original resource run. Original raw stable-worker PIDs were constant; the
problem was that the evaluator did not enforce that condition for future runs.

## Corrected validation

- The resource evaluator now requires the **same Nginx PID set after warmup**,
  not merely two processes and a stable master. A worker repeatedly replaced
  between samples cannot reset memory and still pass. A counterexample gives
  every sample a new worker PID and must fail with otherwise flat RSS/FD.
- Every capacity case takes complete core/wire/count/catalog snapshots **before
  its first actual restart**, then compares immediately afterwards. This includes
  newly completed `limited-*` recovery rows and the successful activation when
  five slots remain. Checking a later restart against an already-corrupted
  baseline is insufficient. A direct `limited_root(1)` mock counterexample changes
  the new row at the first stop and must fail at that restart.
- Case completion also compares the latest complete state across a final service
  restart. Existing and newly added request columns, timing, target, result and
  terminal states are covered, not only total row counts.
- Once the soak's finite creation phase ends, every steady cycle compares the
  whole normal/root catalog. It also retains creation/final/post-stop catalogs
  and compact per-cycle RPC outcomes. Equal-size timing/result rewrites cannot
  hide behind constant disk bytes or terminal-state-only checks.
- Cleanup, configuration restoration and source-change failure cannot leave a
  completed passing result. The early run that still placed the first snapshot
  too late was deliberately interrupted, retained as failed/incomplete history,
  and excluded from the new qualification. Earlier passing reports describe
  their own harness/source and are not silently relabeled as new coverage.

The worker, RSS, FD, process-count and disk checks are complementary. Numeric
limits remain the original 4096 KiB RSS span, 1024 KiB growth and FD span 2; none
was raised after observing results. There was no earlier user-specified numerical
budget. The source manifest is captured before measurement and checked unchanged
at completion. This is reproducible controlled execution, not a tamper-proof
external timestamp proving the entire development history. A bounded small
measured trend below these limits is not evidence of zero leakage.

## Evidence and limits

The final corrected source requires a new full 1200-second run; old samples are
not reused to claim its checks ran. Reviewers inspect code/counterexamples and raw evidence; that review is not a
second independent VM execution. The recorded isolated VM execution provides
the actual installed-service observations.

The installed artifact/CLI and fixed systemd units remain the product under test;
read-only catalogs and resource probes do not implement recovery. No application
module, unit template, privilege allowance, license or repository visibility
change is introduced by this review.

Root recovery still lacks a five-row reservation and can partially complete
while remaining closed. Capacity restart checks are service restarts, not new
full-capacity VM poweroff experiments. Long-term stability, rollover/reset,
sudden power loss, boot zero-gap and production-store migration remain
unqualified. See CLOSEOUT.md for final source-bound results and reproduction.

## Corrected execution outcome

The corrected run completed 1200.182 seconds, 121 samples and 103 stable samples.
All 107 steady-cycle full-history comparisons and creation/final/post-stop
catalogs match. Stable writer RSS spans 92 KiB (21840–21932), fitted growth is
26.41 KiB, first/last median difference 32 KiB, FD is fixed at 5; Nginx worker
identity, aggregate RSS (13432 KiB) and FD (15) remain fixed. No numeric RSS/FD
threshold was changed. All nine corrected capacity cases compare their complete
state at the first and final restart, with new recovery/activation rows included.

Linux unit evidence has 136 tests, zero failures/errors/skips. Installed deployment
and runtime storage-fault regressions are recorded separately; all final current
reports must match the same source and host-linked digests. These are controlled
measurements and reviewable assertions, not an independent hardware replication.
