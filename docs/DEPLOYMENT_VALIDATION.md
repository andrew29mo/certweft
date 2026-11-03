> Scope update: [REBOOT_VALIDATION.md](REBOOT_VALIDATION.md) separately qualifies
> three preserved-state normal VM poweroff/start cases. This document describes
> the process/deployment matrix; its original full-regression counts below are
> historical. The eight deployment cases are rerun at the current
> [capacity/resource closeout](CLOSEOUT.md) source.

# Installed deployment validation

This milestone qualifies manual installation/start/stop, real issuer credentials,
certificate activation, controlled recovery and bounded process restart. It does
not qualify machine reboot, automatic boot recovery, sudden power loss, boot
zero-gap, long-running resource stability, remote CA networking or D-state exit.
The repository remains Private and has no selected license.

## Reproducible disposable VM workflow

A new Colima ARM64 profile was created for this work, independently of the older
`closeout` profile. Its Ubuntu 24.04 image was provisioned with documented OS
packages and checksum-verified Smallstep CLI 0.31.0 / CA 0.30.2. The initial check
found no Certweft deployment. Development attempts reuse that provisioned VM,
resetting only application paths/accounts/units owned by the fixture. This is a
clean application install on a provisioned VM, not a newly downloaded OS image
for each retry or a bare-metal qualification.

Build prerequisites and manual operation are in [INSTALL.md](INSTALL.md). In the
disposable VM, first create `/opt/certweft` as a Python 3.12 venv. Then:

```sh
sudo env CERTWEFT_DEPLOYMENT_VM=1 PYTHONDONTWRITEBYTECODE=1 \
  timeout 360 python3 tools/deployment_vm.py
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Do not run this fixture on a production host. It installs fixed paths and service
accounts, uses a private local CA and can reset a prior installation marked as
fixture-owned. Unmarked existing application state/account names are refused.
It never modifies another Nginx unit or clears arbitrary units' failure state.
The CLI console entrypoint was also checked under the operator identity; the
fixture invokes the same installed CLI through isolated Python module imports.

Reports initialize to in_progress/passed=false. A nonzero exit, timeout, missing
final result, source change, failed scenario or failed cleanup is not passing
validation. JSON and escaped HTML carry the same payload; archived attempts are
not silently replaced with a passing interpretation.

## Installed implementation and identity

The runner builds the actual wheel, records its SHA-256, installs it into
`/opt/certweft`, and compares **every packaged module/resource** against its wheel
bytes before and after the scenarios. It verifies the imported module path and
actual systemd main command/cwd. Unit and executor imports are isolated from the
checkout. The source manifest now recursively includes package assets and
pyproject.toml, as well as code/tests/policy/tools; earlier flat manifests retain
historical scope.

Nginx identity in installed mode uses the fixed root-owned unit bytes and loaded
command, no drop-ins, MainPID, InvocationID, start time and a pidfd. This avoids
granting the root writer CAP_SYS_PTRACE solely to inspect another root process's
executable. The manager and host root are trusted. Source-run executable checks
remain unchanged. The writer still runs as root with only CAP_CHOWN; the signer
is a separate non-login UID with zero effective capabilities. This is separation
of the exercised interfaces, not proof against compromised host root.

## Eight real-service scenarios

| Scenario | Required evidence |
|---|---|
| Wheel installation | Installed module location, wheel hash and exact package payload bytes |
| Documented installation/start | Fresh application paths/accounts, actual unit verification, isolated service command, root/CAP_CHOWN/NoNewPrivileges and denied operator private reads |
| Credential delivery/issuance | Real Smallstep signing, signer UID/capabilities, operator denied source/runtime credential and key reads, no password in observed environment or unit journal, credential path/cgroup cleanup |
| Normal activation | Operator CLI COMMITTED, independent new trusted TLS/HTTP 200 and different expected leaf fingerprint |
| Storage fault/repair/reopen | Actual SQLite pager FULL on activation COMMIT, DEGRADED, closed after repair/restart, explicit root helper and successful new activation |
| SIGKILL takeover | Actual unit executor paused after confirmation, main SIGKILL, new invocation only after old executor exit, closed startup, then explicit recovery and rejection of stale activation without changing the wire leaf |
| External lease owner | Real installed executor outside unit cgroup retains inherited lifetime lease while awaiting input; unit exits exactly 73 without auto-restart, takeover only after that executor exits |
| Restart limiting | Three starts within the configured 60-second window, this run's journal rate-limit message, explicit start refused before reset, operator reset/start still closed |

The external lease case does not claim a mutating stale executor coexists with a
new writer; it demonstrates that coexistence is refused. The SIGKILL case tests
the real installed executing worker and cgroup cleanup. No VM shutdown/reboot is
performed. The fixed helper's five root requests preserve the existing contracts
and original deadlines. Prior guard, cancel, stale-authority and failure matrices
were rerun at the original deployment milestone; they remain historical source-run
reports rather than new reboot-stage runs.

## Measurements and interpretation

Per-case elapsed time, CLI activation elapsed time, SIGKILL-to-observed-new-ready
interval, process RSS/HWM and final journal-directory disk counters are in
`evidence/deployment.json` and its HTML counterpart. These are actual VM
observations, not SLAs, hard deadlines or performance comparisons. Readiness after
crash still means admission is closed, not successful certificate recovery.

RSS/HWM samples are identified by role: writer, signer Python process and paused
executor. They are not total system/VM memory, the full signer process tree, a
complete lifetime peak or a resource-leak test. State disk counters sum unique
regular-file inodes, excluding symlink targets, directories/filesystem metadata,
logs, installed interpreter, CA data and package/toolchain storage. They describe
the end of this bounded sequence, not bytes per activation or disk exhaustion
coverage. The storage-failure scenario is SQLite FULL, not a newly qualified
installed-service physical disk-full/read-only matrix; those faults remain in
separate source-run reports.

## Latest deployment rerun (observations, not guarantees)

| Observation | Result |
|---|---:|
| Installed operator submit → COMMITTED and independently checked new TLS leaf | 0.77 s |
| Main SIGKILL → observed new management socket, admission still closed | 1.11 s |
| Writer RSS at initial-ready sample | 21,748 KiB |
| Signer Python RSS during credential observation | 6,248 KiB |
| Paused executor RSS before crash | 23,380 KiB |
| End-state unique regular files | 24 |
| End-state logical / allocated regular-file bytes | 102,242 / 176,128 |

The role, timing and storage scope restrictions above apply to every row. In
particular, 1.11 seconds is not a certificate-restoration time or recovery upper
bound. These are separate process snapshots and must not be summed into a total
service memory claim.

## Failures found during development

Retained failed/incomplete attempts include:

- Nginx default temporary/PID paths conflicting with strict read-only mounts;
  dedicated runtime paths and the required explicit writer allowlist fixed this.
- `/proc/exe` access denied under the narrower capability set; the installed
  systemd identity binding replaced that access rather than adding ptrace power.
- Socket mode changes after ownership transfer requiring an unnecessary capability;
  mode now precedes chown.
- Package installation under a private umask hiding CLI modules; code installation
  uses 022 while secret/state permissions remain explicit.
- Public certificate group inheritance failing for the signer; a public-output
  supplementary group fixed it without giving the operator key-group access.
- A harness assumption that `Result` must equal `start-limit-hit`. On the tested
  systemd, it retained `signal`. An unsafe subsequent PID-0 signal killed the
  verifier; its in-progress report is failure, not recovery evidence. Signals now
  require a live unit-owned PID, a matching invocation and a pidfd. Rate-limit
  qualification also requires the new journal event and explicit start refusal.
- A later unique-inode measurement correction changed the source during a prior
  regression; that run was invalidated and rerun rather than counted as passing.

The fixture stops its units and private CA and verifies cgroup/MainPID cleanup.
Root-owned installation and private diagnostic CA files remain inside the stopped
VM for review; they are not uploaded. The explicit marker protects reset
ownership. Preserved-state boot/reboot recovery is now a separate qualified stage;
storage faults across reboot are now separately qualified for ENOSPC, read-only
and SQLite FULL. Finite-capacity and one bounded resource window are separately qualified in
CLOSEOUT.md; automatic rollover/GC and long-term stability remain unqualified.

## Original deployment qualification record

The fixed version passed all eight scenarios plus 120 Linux units and 148
separately rerun source-service VM regressions. Ten then-current JSON/HTML reports
match the complete 54-file source manifest; installed package payloads match the
wheel and that milestone’s source. Those counts do not include expected-failure controls
as extra passing VM scenarios. All required unit/cgroup, CA-process and temporary
regression cleanup checks passed. Private installed state/diagnostic CA files are
retained only inside the stopped evaluation VM.

## Primary references

- [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
- [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Smallstep CLI release](https://github.com/smallstep/cli/releases/tag/v0.31.0)
- [Smallstep CA release](https://github.com/smallstep/certificates/releases/tag/v0.30.2)
