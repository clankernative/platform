# Security reporting

Please report vulnerabilities privately through
[GitHub's security advisory form](https://github.com/clankernative/platform/security/advisories/new).
Do not put credentials, company application code, databases or production evidence
in a public issue. Include the platform revision, supported host/runtime profile,
a minimal synthetic reproduction, impact and any suggested mitigation.

The current development line is supported on a best-effort basis. There is no
response-time SLA or supported historical release branch yet. Security fixes and
advisories will identify affected revisions and the first patched version.

The runtime's security boundary is documented in [security admission](docs/SECURITY-ADMISSION.md)
and [edge identity](docs/EDGE-IDENTITY.md). Development login URLs and local operator
assertions are not production authentication. Company's instances, application
sources, backups, evidence and credentials remain private and under the operator's
control. Do not upload the `artifacts/` directory with a vulnerability report.
