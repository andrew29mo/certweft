# Reproduce the bounded explorations

For the current startup policy use [RESTART_GATE.md](RESTART_GATE.md).
The original exploration and old VM recovery runners below describe historical
checkouts; they do not qualify current automatic recovery.

Use a disposable isolated Ubuntu 24.04 ARM64 VM, Python 3.12, real systemd,
OpenSSL 3, Nginx, root, mount support, and unused loopback ports 19090/19443.
This is an existing VM with fresh private application fixture paths, not a clean
OS installation qualification. Do not use a production host.

Install nginx and curl using the VM package manager. Download Smallstep CLI 0.31.0
and step-ca 0.30.2 ARM64 releases from the official Smallstep distribution and
verify the upstream release checksums. Set CW_STEP and CW_CA to their absolute
executable paths. The CA is created solely for this disposable experiment.

From the repository in that VM:

```sh
python3 -m unittest discover -s tests -v
sudo env CW_STEP="$CW_STEP" CW_CA="$CW_CA" timeout 150 python3 tools/explore.py
```

A nonzero exit, outer timeout, missing final report or failed case is failure.
Inspect both passed and cleanup_error. Run report files are overwritten only
with the previous completed JSON retained in evidence/attempts. At invocation start, the prior report is archived and an in-progress failure
marker is written. A killed process leaves that marker rather than a passing
result. Verify current source fingerprints and invocation outcome; never treat
report existence as success. Source changes during a run invalidate it.

Private fixtures remain under /var/tmp/certweft-* (0700), entirely inside the VM.
They include test CA keys, provisioner password and logs; never upload them.
The runner stops its own Nginx and CA; after a forced outer termination inspect
processes and mount state before reuse. Discard only your disposable VM when
finished. No host routes, host trust store or existing Nginx config are changed.

Timings describe this VM workflow; RSS is the Python driver's process high-water
mark, not total service memory or a comparison. Private fixture bytes are logical
file sizes including CA database/log files, not allocated filesystem blocks.

For the current source-run storage matrix, dedicated loop-filesystem prerequisites,
cleanup and measurement limits, follow [STORAGE.md](STORAGE.md). These storage
cases do not require the Smallstep binaries. The older exploration and CSR
authority reports retain their original source hashes.
