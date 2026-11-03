> Historical review at f0ee181. The later [storage-fault reboot stage](STORAGE_REBOOT.md)
> adds separate evidence and fixes the observer's SQLite descriptor lifetime.
> This review's original untested list describes its own stage, not a new rerun.

# Preserved-state reboot review and corrections

The review checked the installed-service recovery stage against the actual
service/Gate/recovery/backend code, committed VM evidence and JSON/HTML. It found
validation/provenance weaknesses, not a demonstrated new recovery-code defect.
No application module, privilege allowance, unit template or license changes were
needed for these corrections.

## Corrections

- **Generic FAILED was insufficient:** a broken executor that rejects every
  request could also satisfy the stale-authority assertion. Each boot case now
  uses the same valid candidate for an old-CAS negative control and a fresh-CAS
  positive control. The old request must be FAILED/Rejected with unchanged core
  and wire; the fresh request must actually COMMIT and serve the exact different
  leaf. The CLI result exposes an error class, not an exact stale-reason string.
  A unit counterexample rejects blanket failures and fake success without a
  matching changed wire leaf.
- **Bind observation to the running boot:** compare the observer with both the
  old and currently running kernel boot IDs. Recheck the live writer's PID,
  invocation, isolated installed command/cwd, root UID, CAP_CHOWN and
  NoNewPrivileges, plus exact unit and sole test drop-in bytes on every boot.
- **Retain auditable decisions:** reports now retain closed-Gate/fresh-CAS denial,
  root recovery response and all five persisted step histories, stale history,
  successful fresh activation and exact candidate/committed wire fingerprints.
  Pending candidate identity is checked exactly, not merely “not committed.”
- **Record the host side:** the bounded host runner records guest poweroff
  transport status, observed manager Stopped, same-profile Running and changed
  boot IDs, paired with the VM evidence. It does not accept an SSH disconnect as
  success, upload raw private host logs, or change another VM. Its final report
  includes the exact VM-report digest and context-restoration result.

## Preserved conservative contract

Root reopening is not permanent permission across later service restarts. A
session that started closed and was explicitly reopened remains ineligible for
a clean-stop receipt; a later normal stop/start still requires recovery. This
was already the selected contract, not a new regression. Five root rows per full
workflow and 16 total combined root rows make repeated recovery finite. This
fixture uses 15 root rows; no history reset/rollover or indefinite recovery claim
is introduced.

A candidate may still be served after boot until root explicitly restores the
committed leaf. A ready management socket is neither automatic rollback nor
proof of reopened update permission. The reports retain this interval directly.

## Verification scope

See REBOOT_VALIDATION.md and current source-bound JSON/HTML for the actual
reproduction, measurements and counts. Negative controls challenge the exact
observer/control functions; VM cases exercise the installed wheel, fixed Nginx
and writer systemd services, real TLS and explicit root workflow. Old reports and
failed/invalidated attempts retain their historical source scope.

Sudden power loss, boot zero-gap, storage fault across reboot and unbounded
stability remain untested. These results do not qualify arbitrary PKI, external
network availability, root-compromise resistance or general production safety.
