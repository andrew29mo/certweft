# Public repository checks

The maintainer authorized Public visibility after the private audit and MIT
adoption. The repository is andrew29mo/certweft, default branch main. LICENSE is
MIT, and the GitHub license endpoint recognizes MIT. Current README, installation,
architecture and licensing pages reflect Public visibility; earlier milestone
records retain their historical context.

Anonymous HTTP requests successfully retrieved README, LICENSE, the final unit
JSON/HTML and capacity/resource JSON. Eight current report pairs agree with their
escaped HTML. All recorded implementation/test/tool hashes match the checkout;
the only manifest difference is the explicitly documented MIT packaging metadata
change in pyproject.toml. Historical evidence has not been rewritten as a new run.
The final Linux unit record remains 136 passed, and the resource window remains
1,200.182 seconds. This publication check does not extend runtime qualification
or claim a remote CI pass.

## Security inspection

At the initial public inspection:

- Sole collaborator: repository owner andrew29mo.
- No Actions workflows; Actions enabled with all actions allowed. Default workflow
  token permissions are read-only, with PR review approval disabled.
- No active rulesets or classic main branch protection.
- Secret scanning, push protection, Dependabot security updates and vulnerability
  alerts are disabled. Private vulnerability reporting is disabled.

## Authorized security configuration

After explicit maintainer approval, the GitHub API read-back confirmed:

- Secret scanning and secret-scanning push protection enabled.
- Dependabot vulnerability alerts and security updates enabled. This does not
  claim scheduled version-update PRs or a completed dependency/security scan.
- Private vulnerability reporting enabled.
- Actions disabled; no workflows exist. Retained workflow defaults are read-only,
  with PR review approval disabled.
- Active main ruleset prohibits deletion and non-fast-forward pushes and requires
  linear history. No bypass actors, mandatory PR or required status checks were
  added, preserving single-maintainer direct fast-forward commits.
- Public visibility and sole-owner collaborator access unchanged.

These are configuration read-back checks. No real secret was pushed and no
force-push/deletion attempt was made to test enforcement. Enabling a scanner is
not evidence that its initial history scan has completed or found no secrets.

The prior content/history privacy scan and its limitations are documented in
PREPUBLIC_REVIEW.md. Current main metadata uses GitHub noreply; this does not
certify erasure of old objects from remote caches. No VM images, credentials,
private keys, state databases or build archives are published by this change.
