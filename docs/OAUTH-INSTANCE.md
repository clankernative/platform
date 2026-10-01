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

Replacing the selection and its key provider happens under one write lock.
In-flight confirmation holds the read lock through readiness, key acquisition
and the final SQLite commit or rollback. If replacement wins, a retired proof
cannot commit. If confirmation wins, replacement waits until its local settlement
finishes. An empty selection revokes subsequent approval without acquiring a
GCP token or constructing a key provider. This is a local host ordering guarantee;
external readiness still needs its independently qualified freshness bound.

The explicit GKE token source uses the fixed metadata service token endpoint,
`Metadata-Flavor: Google`, bounded responses and timeouts, and a usable Bearer
token lifetime. It requests a token on each key read and disables proxies and
redirects. This follows [Google's GKE workload identity interface](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).
The selected Kubernetes service account and named-secret IAM policy must be
qualified separately; parsing a metadata token is not evidence of that policy.

## Private shell-to-app transport

Each app host owns its SQLite database, custody keys and current approval
authority. `StoredAppApprovals` pins one app and one host-selected database path;
`AppApprovalReceiver` handles only `POST /_day2/oauth/approval`. The host must
initialize the ordinary principal and OAuth tables and mount this reserved
handler before ordinary app dispatch. Apps cannot register this protocol as a
command or query.

The existing instance document adds one optional field:

```json
"oauth_shell_transport": {
  "service_account": "security-shell@company-tools.iam.gserviceaccount.com"
}
```

The instance repo selects this dedicated Google service account. Receiver
origins and IAP backend audiences reuse `apps[app].edge`; the human assertion
uses the independently selected `security_shell.iap_audience` and company hosted
domain. No platform hostname default or second transport endpoint catalog is
introduced. Installations without this field cannot compose private OAuth RPC.

Every request carries two independently verified assertions:

- IAP supplies a workload assertion at the receiver's app backend audience;
  its email must equal the selected shell service account.
- The shell forwards the original signed human assertion from its own IAP
  backend in the bounded private request body. The app host verifies that shell
  audience and hosted domain, checks the stored attempt owner, and binds the
  human email to the immutable IAP subject in its ordinary principal table.

The workload never becomes the app's effective human. A human assertion cannot
authenticate the workload endpoint. Shell cookies, reauthentication codes,
provider tokens, PKCE verifiers, database paths and custody key material never
cross this transport.

The connect host creates identifiers with `shell_transport::scoped_attempt`:
a digest of the installation/environment/app namespace plus a fresh 256-bit
random suffix. The browser carries only this opaque identifier. The shell
contacts exactly its selected owning app; an unrelated app outage cannot block
that lookup. Namespace routing does not confer authority: the receiver checks
its own namespace, durable ownership, verified human and current contracts.
Unrouted kernel test identifiers are not accepted by the private RPC receiver.

The app returns a bounded preview of the verified provider identity, exact
scopes, consent text, challenge and current contract digests. A one-use shell
session binds that complete preview and the human's IAP subject. Changed
presentation requires a new session; the shell cannot silently sign a newer
preview when submitting the old form. The fresh attestation signs the preview
digest as well as the pending identity and authentication time. The app
reconstructs that digest under current authority and rechecks attempt state,
custody, expiry, generation and epoch before its final local activation. It
reads its clock again after key acquisition. No network operation runs inside
the SQLite settlement transaction.

`SecurityShell::from_gke_instance` composes `RemoteApprovals`, the selected shell
edge and Google reauthentication adapter. `ArtifactShellSigner` obtains only the
selected attestation key; its GCP key provider excludes custody key roles. The
constructor returns the signer handle for later selection replacement. The
shell has no app database registry or filesystem mounts. App hosts retain their
own `ArtifactApprovalAuthority`, custody keys and attestation verification key.
The host supplies a qualified `PrivateBearerSource` for each selected IAP
receiver; ambient app credentials or a browser token are insufficient.

Requests and responses have fixed versioned JSON schemas, bounded bodies and
deadlines. Receivers reject unknown or duplicate fields, wrong paths, methods,
Host headers, audiences and namespaces. The client disables proxies and
redirects and sends confirmation once. Response loss is ambiguous; it does not
trigger an automatic retry. A subsequent lookup observes durable settlement,
and replay cannot activate the same attempt twice.

## Remaining runtime work

The next runtime slice must wire host startup and connect attempt creation,
implement the qualified IAP workload credential source, and deploy the shell
with its dedicated service account, backend access and attestation-only secret
IAM. App-host IAM separately needs its custody and verification keys. The
existing edge bootstrap does not establish these runtime policies.

This layer does not start a shell workload, publish a reviewed Google Calendar
provider, establish live readiness, create a Google web client, or enable OAuth
on an installation. Provider/registration readiness and the live
connect/use/refresh canary remain separate qualification work.
