# Licensing and third-party scope

Certweft-owned source, tests, scripts, service templates, documentation and
selected validation reports are licensed under the [MIT License](../LICENSE),
copyright 2026 Andrew Yuan. Repository visibility is Public. Earlier
milestone descriptions of an unselected license are historical, not current terms.

## Dependency inventory

`pyproject.toml` declares no third-party Python runtime requirements. Imports in
certweft/, tests/ and tools/ were inspected: they use Python's standard library,
Certweft modules and local test/tool helpers. The wheel contains Certweft code
and its four service/configuration assets, not external executables, libraries,
CA credentials, VM images or OS packages. There is no bundled third-party model
or dataset. Selected reports are project-generated evaluation evidence.

| Component | Relationship | Upstream terms checked |
| --- | --- | --- |
| Python 3.12 | Separately installed interpreter/standard library | [PSF license and incorporated-component notices](https://docs.python.org/3.12/license.html) |
| SQLite | Used through Python sqlite3, not vendored | [Public domain](https://www.sqlite.org/copyright.html) |
| setuptools >=77 | Build backend, not application runtime | [MIT](https://github.com/pypa/setuptools/blob/main/LICENSE) |
| Smallstep CLI 0.31.0 | Separately installed signing CLI | [Apache-2.0](https://github.com/smallstep/cli/blob/v0.31.0/LICENSE) |
| Smallstep CA 0.30.2 | Separate evaluation CA process | [Apache-2.0](https://github.com/smallstep/certificates/blob/v0.30.2/LICENSE) |
| Nginx 1.24 | Separate dedicated TLS service | [BSD-2-Clause](https://github.com/nginx/nginx/blob/release-1.24.0/docs/text/LICENSE) |
| OpenSSL 3.0 | OS CLI and Python TLS support | [Apache-2.0](https://github.com/openssl/openssl/blob/openssl-3.0/LICENSE.txt) |
| systemd 255 | OS service manager invoked through fixed units/systemctl | [LGPL-2.1-or-later, with component exceptions](https://github.com/systemd/systemd/blob/v255/README) |

The inspected integration invokes separately installed components and does not
copy their implementations into Certweft. No conflicting requirement was found
for applying MIT to the Certweft materials shipped here. MIT does not relicense
those external components. Consult the installed distribution's copyright files
for package patches, optional modules and transitive dependency notices.

This is an inventory for the source/wheel currently distributed, not a license
bill of materials for an entire Ubuntu/Colima VM. Colima, Linux, build/install
tools and their dependencies remain separate host/evaluation tooling. No VM or
combined appliance is distributed. Anyone later distributing external binaries,
modified dependencies or a combined image must separately preserve their
applicable notices, licenses and source/relinking obligations. That broader
redistribution has not been qualified by this review.

## Packaging and evidence

The package metadata declares `License-Expression: MIT` and includes LICENSE
using the setuptools license-files mechanism. Historical validation JSON/HTML
remains unchanged: modifying packaging metadata does not constitute a new
runtime or performance experiment. No new runtime, recovery or timing claim is
made by adopting the license.

The license-adoption check built both sdist and wheel with Python 3.12 in the
isolated Linux VM (setuptools 84.2.1, build 1.6.1). Both archives contain the
exact LICENSE bytes and MIT expression; the wheel declares no Requires-Dist
and all 22 package files match the checkout byte-for-byte. Build artifacts
and detailed checks remain in ignored results/license-packaging/. This check
does not replace or extend the recorded runtime/VM qualification.
