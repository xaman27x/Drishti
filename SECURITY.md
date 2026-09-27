# Security policy

## Supported versions

Security fixes are provided for the latest published Drishti release. Older demonstration builds
and untagged container images are not supported for production use.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's **Security â†’
Report a vulnerability** private reporting flow:

<https://github.com/xaman27x/Drishti/security/advisories/new>

Include the affected version or image digest, deployment mode, reproduction steps, impact, and any
suggested mitigation. Do not include real organizational logs, credentials, parser signing keys,
or other sensitive evidence.

The maintainers will acknowledge a complete report, reproduce it in an isolated environment,
assess affected versions, and coordinate remediation and disclosure. Release artifacts can be
verified using the checksums, SBOMs and GitHub attestations described in
[`docs/releasing.md`](docs/releasing.md).

## Scope notes

Parser-registry signing keys, MinIO credentials, Kafka authentication, TLS certificates and
retention controls belong to the deploying organization. The example Compose credentials are for
local evaluation only and must never be reused in staging or production.
