# Selected outbound OAuth connections

An app registers semantic connection requirements once, in
`App.definition.connections`. The build derives `connection_declarations` from
the checked worker; artifact admission compares them with the compiled output.
The instance selects those registrations in `apps[app].oauth_connections`.
Neither the instance nor the app supplies a provider scope map.

The private host composition in `oauth/admission.rs` loads each selected artifact
from its ordinary instance-relative `artifact` path. It requires the current
artifact format, the matching app namespace, an exact declaration registration
and nominal requirement digest, and a matching reviewed provider profile. The
host catalog derives scopes for exactly the declaration's actions. Unselected
declarations confer no OAuth authority.

## Instance contract

Each entry in `oauth_connections` uses the declaration's registration name as
its key and the shared `day2-capabilities::oauth::OutboundConnectionBinding`
contract as its value:

| Field | Selection |
| --- | --- |
| `namespace` | Installation, environment, app and positive binding generation. |
| `requirement` | Digest of the app-owned nominal requirement contract. |
| `profile` | Reviewed host profile ID and exact revision. |
| `registration` | Provider registration ID and qualified evidence revision. |
| `custody` | Custody binding covering the exact verifier and encryption providers. |
| `security_shell` | Qualified security origin reference. |
| `account_binding` | Human mapping, external approval or installation account binding. |
| `shell_attestation` | Independent binding covering the origin and attestation key provider. |
| `product_return` | Approved product navigation reference. |
| `custody_verifier_secret` | Name in the existing `control.secrets` catalog. |
| `custody_encryption_secret` | Name in the existing `control.secrets` catalog. |
| `shell_attestation_secret` | Name in the existing `control.secrets` catalog. |

Secret selections reuse `SecretProvider::GcpVersion`: numeric project number,
secret name and positive numeric version. Aliases such as `latest`, missing
providers, reused physical key versions and stale custody/attestation revisions
fail qualification. Secret bytes do not appear in the instance, artifact or app
database. For explicit external-account approval, `account_binding` must equal
the selected `shell_attestation` binding. A mapped-human account reference remains
a subject mapping; it is not reinterpreted as an approval key.

The instance repo owns company addresses. Its `security-shell-edge` values
select the hostname, and the published edge contract supplies
`security_shell.origin` and `security_shell.iap_audience`. The platform has no
company hostname default. See [the GKE installation security origin](../deploy/gke/README.md#installation-security-origin).

## Callback and current approval lookup

The host derives the callback namespace from the complete selected namespace,
requirement/profile and resource references. The registration ID participates;
its evidence revision is excluded to avoid a circular dependency on the derived
callback. The callback reference additionally binds the security origin and
profile. A binding generation change invalidates old callbacks without creating
a second logical slot. The registered URL is shared across the humans using that
binding; each private attempt still pins its exact owner, unique slot, session
and one-time state.

Static compatibility does not establish readiness. An `OutboundReadiness`
implementation must check current external qualification for the exact selected
binding and owner on every request. `ArtifactApprovalAuthority` compares those
facts with the selection, then applies the existing protocol and registration
qualification guards before obtaining all three exact-version key leases.
Missing readiness, a mismatched owner, substituted evidence or a retired
selection cannot obtain keys. Mapped-human and installation connections do not
enter the external-account approval shell.

`SecurityShell::from_gke_instance` composes that authority with the selected
shell edge, GKE key provider and Google reauthentication adapter. It returns the
authority handle for subsequent selection replacement. This private constructor
does not mount a listener or choose an app storage transport.

Replacing the selection and its key provider happens under one write lock.
In-flight lookups hold the read lock through readiness and key acquisition; once
replacement returns, no lookup can finish using the retired snapshot. An empty
selection revokes approval without acquiring a GCP token or constructing a key
provider.

The explicit GKE token source uses the fixed metadata service token endpoint,
`Metadata-Flavor: Google`, bounded responses and timeouts, and a usable Bearer
token lifetime. It requests a token on each key read and disables proxies and
redirects. This follows [Google's GKE workload identity interface](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).
The selected Kubernetes service account and named-secret IAM policy must be
qualified separately; parsing a metadata token is not evidence of that policy.

## Remaining runtime work

This layer supplies private composition and revocation checks. It does not start
a shell workload, publish a reviewed Google Calendar provider, establish live
readiness, create a Google web client, or enable OAuth on an installation.
The shell transport must preserve app-owned SQLite storage and failure domains;
the dedicated browser shell must not require mounting every app's database in a
central pod. Runtime transport, provider/registration readiness and the live
connect/use/refresh canary remain separate qualification work.
