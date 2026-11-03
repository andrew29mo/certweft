# Pre-publication review

## Current decision

The repository remains **Private**, version 0.0.2, with **no selected license**.
No LICENSE/SPDX permission grant has been added. Publishing visibility and
choosing a license are separate maintainer decisions. No new functionality,
third-party source bundle or runtime dependency was introduced by this review.

The current README now describes implemented behavior and explicit boundaries;
the earlier milestone narrative is retained in historical design/evidence guides.
ARCHITECTURE.md and REPRODUCE.md point to the current installed lifecycle and
closeout instead of presenting older deployment/recovery gates as still open.

## Evidence checked

Seven current pairs—capacity, soak, closeout-host, closeout-units,
boot-bootstrap, deployment and storage—have matching JSON/escaped HTML and the
same complete 62-file implementation/test/tool manifest. Source bytes match those
manifests; installed package resources match wheel payloads. Host digests match
the finalized capacity/resource JSON. Documentation is reviewed separately; it
is not part of that implementation/test/tool manifest.

Recorded results are 136 Linux tests (no failures/errors/skips), nine capacity
cases, eight installed deployment cases, fourteen source-service runtime
storage-fault cases, and a newly rerun 1200.182-second / 121-sample resource window.
Setup matrices overlap and are not summed into independent benchmark trials.
Old boot/storage-boot matrices and archived failed/interrupted/source-changed
attempts retain their own scope. They are not relabeled as current reruns.

The corrected capacity cases compare all old/new request columns across each
first and final service restart. Resource checks fix writer/master identity and
stable worker PIDs, compare full history throughout and after stop, retain the
original RSS/FD thresholds and distinguish state-disk scope from total deployment
size. These are bounded VM observations, not leak-free, performance-SLA or native
macOS service qualification. No remote CI pass is inferred from local records. An additional final-review
run in prepublic-units.json/html passed all 136 Linux tests without skips; the
implementation/test/tool manifest is unchanged. The VM’s 22 installed package
files were checked against the recorded wheel payload.

## Privacy and upload scope

A content scan covered tracked files and all 768 reachable Git blobs present
before this documentation review. It found no private-key material, recognized
GitHub/AWS key patterns, personal home paths or personal-mailbox addresses. This
is a pattern-based check, not a guarantee that every possible secret format can
be recognized. No tracked keys/PEM stores, databases, VM images, raw logs, wheels,
bytecode, virtual environments or personal AGENTS/settings were found. Ignore
rules now also exclude common credential/data/log/build artifact formats; this
does not replace reviewing staged files.

Git metadata is a separate finding: one initial commit uses a machine-local
email identity; later commits use GitHub noreply. It is not a receiving mailbox
or credential, but includes local account/host attribution. A maintainer decision
is required before publication: retain that historical attribution intentionally,
or authorize a metadata-only history rewrite. Rewriting remote history changes
descendant commit IDs and is not performed under this review's routine-edit
permission. Existing code/source evidence must remain byte-identical in any
metadata-only candidate. A rewrite does not itself certify removal from remote
object caches. This unresolved decision is not called a clean publication pass.

Private CA/state fixtures remain only inside the stopped evaluation VM; report
content is selected diagnostic data, not raw host execution logs. Remote inspection found the sole collaborator to be the owner and zero
workflows/runs. Actions is enabled with all actions allowed; this review does not
claim that future workflow execution is hardened or that secret scanning is
enabled (the repository API did not expose its security-analysis status). No
visibility, collaborator, Actions setting or external-message change was
authorized or performed here.

## Boundaries to preserve in any public description

- One fixed localhost/IPv4 Nginx instance, one CA and P-256 key policy; same-key
  credential-authorized CSR reissuance is not possession-only renewal.
- Host root/systemd trusted, no arbitrary unit or remote-management API.
- Full/read-only storage may leave management unavailable and a stale RUNNING Gate
  file; the candidate may remain served until explicit root restoration.
- Recovery is five separate operations without a five-row reservation. A partial
  workflow can remain closed, and later restart of a recovered store closes again.
- 64 normal rows, 16 root rows, 16 generations; no qualified GC/reset/rollover or
  production-store migration. Full-capacity restart checks are service restarts.
- No sudden power-loss, boot zero-gap, arbitrary physical-media/fsync/returned-
  COMMIT fault coverage, WAN reachability, all-client continuity or indefinite
  resource/rotation guarantee.
