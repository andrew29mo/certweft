# Committed certificate recovery to VERIFIED_CLOSED

The next [closed preparation stage](CLOSED_PREPARATION.md) adds a separate explicit
operation for main-journal/health reconciliation; certificate recovery itself
still has the unchanged boundaries below.

## Scope and API

This stage adds root-only committed-certificate restoration and new TLS
confirmation. Success stops at VERIFIED_CLOSED. No API enables normal updates,
clears STORAGE_FAILED, marks the core READY, reconciles normal activation requests
or issues a clean-shutdown receipt for the isolated session. This is still a
source-run single-host service, not an installed systemd deployment.

After recovery-status and prepare-recovery, submit exactly:

```json
{"op":"recover-certificate","request_id":"restore-001","gate_epoch":"<current prepared epoch>","gate_revision":7,"timeout_seconds":10}
```

Use recovery-request-status with that ID to observe the operation. UID 0 is
required; the body cannot select paths, commands, a different generation, a key,
a certificate, or an old storage-verification result. The service captures the
current committed/core snapshot. STORAGE_VERIFIED history is never reused as
permission to restore or reopen: the full operation performs fresh storage and
journal checks within its own original 1–10 second persisted budget.

Deduplication includes operation kind. Replaying an accepted ID is historical,
never dispatches it again, and never extends time. Using the same ID for
verify-storage and recover-certificate is a conflict. Both share the existing
16 permanent root slots, one live root operation and 128-page control pager cap.
There is no automatic history recycling or extra emergency disk reserve.

## Versioned compatibility

The control catalog upgrades version 1 to version 2 in a SQLite transaction under
the same decision barrier/lifetime lease. A kind column explicitly identifies
legacy rows as verify-storage; stored digest, timing, target, probe and result
are preserved. The live-row index now also covers CERTIFICATE_VERIFIED. All rows
must pass the existing strict budget/digest validation before migration commits.
Unknown/malformed layouts are rejected; failed migration rolls back instead of
repairing or discarding history. Unit tests exercise actual v1-shaped catalogs,
including preserved history and malformed-catalog rollback. This is not a clean
VM package-upgrade qualification or proof of arbitrary future-version compatibility.

## Formal restoration path

The real lease-fenced root recovery executor dispatches on the persisted kind.
It acquires the formal writer lock and, using the original deadline and authority:

1. Revalidates the main journal and fixed target, performs private filesystem
   write/fsync/rename/cleanup and the synchronous reserved SQLite-row write.
2. Uses the formal certificate validator on the captured committed generation:
   chain/root, localhost SAN, serverAuth-only purpose, key match, P-256/signature
   policy and validity margin. Invalid committed material is refused before
   selection. No older-version fallback or validation bypass exists.
3. Selects exactly that committed fragment, tests Nginx configuration and signals
   the frozen master through the formal pidfd identity-checked reload method.
4. Uses the formal confirmer: three consecutive new trusted TLS connections with
   the expected leaf fingerprint, no session reuse and same-connection HTTP 200.
   Then rechecks certificate contents, fixed journal target and current authority.

For APPLYING/DEGRADED the target is the durable committed generation, not the
candidate. For an already COMMITTED normal activation, the newer committed
identity remains the target; it must not be rolled back to an older generation.
Root verification changes only the reserved probe row; restoration changes the
active pointer and Nginx live configuration. Immutable generation bytes, main
core/health/request rows and historical activation results are preserved.

A failure after selection may already have changed service. The result reports
may_have_changed_service and any TLS observation, not a claim that nothing
happened or that rollback succeeded. A bad reload/leaf/HTTP response or expired
budget never earns completed recovery. An invalid/expired committed certificate
keeps isolation; obtaining new trusted material belongs to another explicit flow.

## Closed completion and crash semantics

ACCEPTED -> RUNNING -> CERTIFICATE_VERIFIED -> VERIFIED_CLOSED

CERTIFICATE_VERIFIED is a durable intermediate proof, still a live operation and
not completed recovery. Next the executor publishes a closed gate marker and
commits the final control result, under the decision barrier with current
original deadline checks. The final result carries the exact closed gate token.
recovery-status reports completion_recorded only when the current
VERIFIED_CLOSED marker has a matching durable final record. The gate label alone
is not proof of a completed paired publication and never enables updates.

If final publication fails or expires, the transaction rolls back. The executor
may demote only its own still-current closed marker to VERIFY_REQUIRED. It cannot
overwrite a newer epoch/revision. If storage prevents that demotion, an incomplete
VERIFIED_CLOSED marker can remain, but completion_recorded is false and admission
is still blocked. No hard realtime guarantee is made for fsync/D-state completion;
deadlines guard the cooperative final COMMIT authorization.

Startup always turns an isolated/unclean session into RECOVERY_REQUIRED with a
fresh epoch. Pending RUNNING or CERTIFICATE_VERIFIED recovery becomes INTERRUPTED
or EXPIRED, preserving original timing/target and never resuming automatically.
A final VERIFIED_CLOSED history remains historical. Even successful restoration
is not permission to reopen after restart. A new prepared authority and a fresh
accepted ID can explicitly retry restoration; it does not rewrite the older
request's deadline or outcome. The old executor's inherited lifetime lease fences
takeover until it exits; unknown occupancy is not released by timeout alone.

A positive local TLS observation is a sample, not a proof that all Nginx workers,
existing connections, external clients or WAN paths are healthy. Existing
connection preservation and zero downtime are not qualified.

## VM and unit evidence

[JSON](../evidence/certificate-recovery.json) and
[HTML](../evidence/certificate-recovery.html) run the formal service/root executor
with actual Nginx, OpenSSL and new TLS in the isolated Linux VM. The matrix covers:

- Uncommitted candidate restoration and a newer committed certificate produced by
  a real normal-service activation, requiring exact generation and leaf identity.
- Root-only admission, in-flight/terminal replay, operation-kind conflicts,
  original timing and continued normal-update rejection.
- Expired certificate, wrong SAN, wrong EKU and mismatched private key. The root
  fixture deliberately updates the structural digest to match invalid material,
  so crypto rejection cannot pass solely because a stale digest was detected.
  Each case also requires the formal certificate-validation failure stage and
  expected OpenSSL rejection or key-mismatch reason, after storage checks.
- Wrong live leaf and HTTP 503 via explicit root fixture interference while the
  real executor is paused; both must reach the formal TLS confirmer and fail
  with confirmation_timeout, rather than pass because of an earlier failure.
  Sanitized terminal results are retained in the report; neither earns TLS
  confirmation or completion.
- Expiry after observed TLS and after tentative final-result SQL writes. An
  independent SQLite reader still sees the intermediate durable proof, not
  uncommitted success.
- SIGKILL after selection, reload, TLS, intermediate proof and closed-marker
  publication. Pending control state is read before restart; the old executor
  still blocks takeover. Restart preserves the original record and does not
  replay it. A separately authorized new intent restores correctly.
- SIGKILL after completed recovery: final history remains unchanged, no executor
  is replayed, and the new session is still closed.

Logical main-journal hashes and full immutable-generation hashes are compared.
Pointer/TLS changes are checked against the intended committed target, including
failure cases where service may have changed. Old keys, CA state, raw logs,
configuration and identities remain private VM fixtures, not report payloads.
Root pause hooks and response interference are explicit tests, not public APIs.
Unit ledger tests use fixture proof records to test authority/transaction
boundaries; those tests alone do not establish crypto/TLS correctness.

In the isolated Linux VM with the prerequisites in STORAGE_VERIFICATION.md:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 240 python3 tools/certificate_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 240 python3 tools/recovery_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 180 python3 tools/gate_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 timeout 180 python3 tools/storage_vm.py
```

Nonzero exit, timeout, incomplete reports, source changes or failed owned-process/
mount cleanup are failure. Reports archive earlier attempts and bind exact source
hashes; timings include fixture setup/cleanup, and sampled RSS is not total
Nginx/VM peak memory or a comparative performance result.

## Current validation

At the certificate-recovery milestone, the source passed 66 Linux unit tests
([JSON](../evidence/certificate-units.json), [HTML](../evidence/certificate-units.html)),
17 certificate-recovery VM fixtures, 15 storage-verification fixtures, ten
gate/lifecycle fixtures and fourteen storage regressions. The 66-unit record is historical after the additive closed-preparation stage;
current unit evidence is now admission-units.json/html, linked in REOPENING.md. The VM regression
reports are rerun and each checks exact source hashes and owned-process/mount cleanup. The combined root
history remains 16 slots; more kinds do not increase or recycle that allowance.
A dedicated success case also preserves a preexisting STORAGE_FAILED latch.

## Still pending

Certificate recovery alone does not reset health or reconcile normal requests;
the separate CLOSED_PREPARATION.md operation now prepares these while closed.
Normal admission reopening still requires a future verified handoff. Installed package/systemd lifecycle, actual VM reboot,
abrupt power loss, physical-media corruption, general fsync failure recovery (including recovery-gate directory fsync and
control-catalog COMMIT I/O failures),
D-state cleanup and long-term rotation remain unqualified. Repository remains
Private and no license has been selected.
