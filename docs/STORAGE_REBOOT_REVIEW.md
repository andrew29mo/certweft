# Storage-fault reboot review

The review compared the actual installed-service harness, formal CLI/Gate/root
recovery implementation, original VM evidence and documentation. It found test
coverage/provenance gaps, not a demonstrated new application recovery defect.
The corrections change tests/evidence/documentation, not application modules,
packaged units, privilege allowances, license or repository visibility.

## Corrected controls

1. **An old prefix must reach old history.** The original retry ran after the Gate
   was RUNNING, so the CLI rejected it before looking up the old FAILED request.
   Now every fault first challenges the preboot Gate token while management is
   still closed and requires exactly `stale_gate_authority` with no state change.
   Current authority positively prepares VERIFY_REQUIRED. In the SQLite case,
   retrying the failed preboot prefix must then return `recovery_step_FAILED`,
   read the exact old FAILED history and leave Gate/catalog/core/wire unchanged.
   A new prefix subsequently completes all five genuine root recovery steps.
   ENOSPC/RO admitted no root request while management was unavailable; no old
   failed-prefix row is invented for those cases.
2. **Preserve existing history, not only the pending row.** Before/after catalogs
   now include every normal/root request column. Existing identity/digest/timing/
   target/probe fields cannot change, and old terminal rows must remain entirely
   equal. Pending work may change to INTERRUPTED; old COMMITTED/FAILED results
   cannot be rewritten to manufacture reconciliation success. Negative unit
   controls challenge both result rewriting and deadline/authority changes.
3. **A failed service alone does not prove the storage cause.** ENOSPC/RO startup
   evidence now filters the current kernel boot, systemd invocation and unit,
   requires Python exit 1 and the configured bounded restart count, and verifies
   OSError errno 28/30 plus the expected Gate-persistence/lease-open stage. Old
   boot records and unrelated import failures cannot satisfy that control.
   Reports retain selected raw exception/provenance records. They are not a full
   traceback archive: the Gate source-frame match is an execution-time assertion
   and stage result, not an independently retained raw stack frame.
4. **Repair does not imply admission.** After repair, an actual valid candidate
   and current core CAS submit must still get `recovery_required`. Only explicit
   root recovery permits the later fresh-CAS COMMITTED update and exact new TLS
   leaf. Old core authority still fails with unchanged core and wire.

The helper-level unit controls challenge the actual functions. The VM matrix
uses the installed package/systemd services and real TLS; the read-only observer
and catalog readers do not implement rollback or reopening. Review of those
records is not a second independent execution of the VM experiment.

## Boundaries retained

Normal guest poweroff/start is not sudden power loss. The image-backed ENOSPC,
read-only and SQLite pager-quota faults are not arbitrary damaged-media/EIO
coverage. Management can be unavailable while an old RUNNING Gate file remains;
that file is not live authorization. Nginx can continue serving the candidate
until explicit root restoration. Recovery history remains finite (16 combined
root rows); no reset, rollover or unbounded operation claim was added.

See STORAGE_REBOOT.md for current results, timings, resource scope, reproduction
and cleanup. Failed/historical attempts retain their recorded source rather than
being relabeled as current passing runs.
