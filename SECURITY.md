# Security policy

## Supported versions

No public release is supported yet. A version becomes supported only after its blocking native CI, checksum/SBOM/provenance, manual validation reports, and security-reporting gate all pass. Unsupported source snapshots receive no compatibility or security guarantee.

## Reporting a vulnerability

`PRIVATE_REPORTING_NOT_VERIFIED`

Private vulnerability reporting was not independently verifiable for this repository on 2026-08-13. Therefore publication is blocked. This document intentionally does not advertise an unverified private-report form or ask reporters to disclose exploit details publicly.

Maintainers must enable GitHub private vulnerability reporting, verify the authenticated form from a non-maintainer reporting account, update this policy with that verified channel, and make the verification a release-bound evidence item before publishing.

Until then:

- Do not open a public issue containing exploit details, credentials, OAuth data, tokens, private prompts, personal paths, or canaries.
- Do not send secrets to an address or account not explicitly authenticated by a future supported release policy.
- Public issues may describe a non-sensitive availability or documentation problem only when they reveal no vulnerability detail.

See [`docs/security.md`](docs/security.md) for trust boundaries, integrity and provenance limits, redaction, Cursor isolation limits, WSL separation, recovery, rollback, and uninstall safety.
