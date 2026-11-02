Current installed-package qualification is documented separately in
[INSTALL.md](INSTALL.md) and [DEPLOYMENT_VALIDATION.md](DEPLOYMENT_VALIDATION.md).
The source-run/transient milestones below retain their recorded scope.

# Reopening review and corrections

Scope: the source-run `open-updates` service introduced at ea281ef, its SQL
admission boundaries, executor lifecycle, VM fixtures and report claims.

## Confirmed findings

1. The main-only COMMIT unit used an absent request and accepted any `Rejected`.
   Without the admission guard, the unrelated `commit_not_authorized` rejection
   could still pass. It now uses a valid RUNNING request, live activation budget
   and complete candidate state, requires `recovery_required`, and proves that
   no SQL/checkpoint work or outcome was committed. A second test changes Gate
   authority after SQL writes and requires `stale_gate_authority` plus rollback.
2. Executor inventory I/O occurred after Popen but outside its cleanup block.
   With the **root-only diagnostic setting** `executor_inventory=/dev/full`,
   actual ENOSPC could leave a child waiting for stdin and holding the lifetime
   lease. Repeated calls could lose track of the earlier child. This does not
   establish the same trigger under the default configuration.

All post-launch actions now share a try/finally that terminates/reaps on error,
closes pipes and clears the registered child before another dispatch. Launch,
registration, fatal cleanup and shutdown share a process lock; shutdown fences
later launches. Error/fatal group termination does not depend on leader liveness:
a leader may have exited while a descendant still holds pipes and an inherited
lease. The real-process unit proves that input, descendant exit and lease reuse.
It is not an installed systemd timeout scenario or a D-state qualification.
The exact adversarial Popen/registration versus fatal/shutdown scheduling race
has not been exercised as a separate formal-service VM scenario; its exclusion
here is a source-level locking invariant, not an additional measured result.

## Evidence that challenges the implementation

`tools/admission_vm.py` adds one formal-service inventory-failure case. After the
real closed recovery/preparation chain, it starts the real service with
`/dev/full` inventory, makes two status calls and requires actual ENOSPC. An
independent `/proc` scan of the exact fixture lease inode must find only the
service after each reply. After stop, there must be no holder; repaired
configuration must restart and complete a real status execution. This case
checks launch cleanup; it does not claim an additional successful reopening.
The fault is device-write ENOSPC, distinct from the existing ext4 exhaustion cases.

Four bounded negative controls run in disposable source copies:

- Remove the first COMMIT guard: the corrected test must fail specifically at
  `commit_checkpoint_reached_before_admission`.
- Remove the second guard: Gate crossing must make the corrected test fail with
  `Rejected not raised`.
- Omit cleanup before stdin is closed: the formal service case must fail at
  `inventory_failure_leaked_lease_holder`.
- Skip group termination when the leader exited: the real-process unit must fail
  at `descendant_survived_group_reap`.

Only the designated source file changes in each copy; the working source is not
mutated. Expected-failure controls do not count as extra passing VM scenarios.
Fixture failure cleanup independently kills owned unregistered holders and waits
for both process exit and lease release; a cleanup failure cannot satisfy the
expected-failure message. The real-process unit has independent fallback cleanup
so a broken production reap function cannot leave its test descendant running.

See admission.json/html for these controls and per-case assertions, and
admission-units.json/html for the complete Linux unit results. Current counts
and the separately rerun regression matrices are in RESULTS.md. Archived failed
or older-source records are retained and excluded from current qualification.

## Unchanged boundaries

No confirmed publication/deadline defect was found in the reviewed three-record
handoff. Review agreement alone is not proof: current qualification depends on
the formal service matrix, SQL tests, counterexamples and matching source hashes.
Historical OPENED still differs from live session permission; recovered stores
close on service restart. Reopening uses the dedicated OpenSSL fixture CA;
Smallstep issuance authority remains separately scoped.

Installed systemd deployment, this reopening path's VM reboot, sudden power
loss, hard realtime completion, arbitrary returned-COMMIT/fsync faults, D-state
cleanup and zero downtime remain unqualified. See REOPENING.md for the contract,
quotas and full measurement limits. The repository remains Private, with no
license selected.
