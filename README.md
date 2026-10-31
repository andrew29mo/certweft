# Certweft

Exploratory single-host Nginx certificate activation and recovery backend.
Private project; no license has been selected. This is not the operational MVP.

The minimum implementation validates a candidate, persists activation intent,
selects an immutable configuration fragment, tests/reloads a dedicated Nginx,
and requires three new TLS handshakes with the intended leaf fingerprint and
HTTP 200 on the same connection. Recovery uses the durable committed generation.

## Important discovery

The tested Smallstep CLI 0.31.0 / CA 0.30.2 pair rejects serverAuth-only
`step ca renew --mtls=false` with incompatible key usage. This route is **not
qualified**. The alternative real CA CSR reissuance path preserves the key and
requires provisioner credentials; it is not equivalent to possession-only renewal.
The fixture CA template fixes SAN to localhost. Production credential scoping,
provisioner policy and secret delivery remain design gates before the MVP.

See [independent review and corrections](docs/REVIEW.md).

## Evidence

[JSON](evidence/exploration.json) and [HTML](evidence/exploration.html) contain the
same result, timings and source fingerprints. A passing exploration means its
listed cases passed, including observing the token-renewal incompatibility;
it does not qualify all proposed MVP requirements. Previous completed reports
remain under evidence/attempts. Two runner defects were encountered during
exploration: unsupported CA authentication and JSON serialization of an empty
byte result. The latter run could not publish a complete report; it is not
counted as passing evidence.

See [architecture and remaining acceptance gates](docs/ARCHITECTURE.md) and
[reproduction](docs/REPRODUCE.md). No keys, CA databases or raw logs are uploaded.
