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

### OAuth clients

The optional `oauth_clients` field uses the shared
`day2-capabilities::oauth::ClientCatalog` contract. Client IDs are public metadata;
`credential` names an existing exact-version entry in `control.secrets`:

```json
"oauth_clients": {
  "version": 1,
  "reauthentication": {
    "client_id": "123-reauth.apps.googleusercontent.com",
    "credential": "google_reauth_client"
  },
  "registrations": {
    "calendar_registration": {
      "client": {
        "client_id": "123-calendar.apps.googleusercontent.com",
        "credential": "google_calendar_client"
      },
      "canary_subject": "112233445566",
      "canary_tenant": "example.com"
    }
  }
}
```

These are example identifiers, not created clients. Registration keys equal the
selected `OutboundConnectionBinding.registration.id`; app declarations remain
in admitted artifacts. The reauthentication and Calendar roles require distinct
clients and physical secret versions. Neither client credential may reuse a
custody or attestation key version. Missing providers, unknown fields, inline
secrets and aliases such as `latest` are refused. An absent client catalog remains
compatible with installations without this runtime composition; it cannot start
the GKE OAuth shell.

No URL or scope is stored in this client catalog. The shell's selected edge
derives the reauthentication callback. Admitted app requirements, reviewed
profiles, full binding namespaces and independent shell evidence derive provider
callbacks. Company domains stay in the instance's edge configuration.

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
edge, keyless IAP workload signer and Google reauthentication adapter. Its client
comes from `oauth_clients.reauthentication`; every code exchange reads that
exact Secret Manager version through the explicit GKE token source. No raw
client secret is supplied as a constructor argument or retained between
exchanges. Token exchange disables proxies, redirects and automatic retries,
bounds the response and refuses duplicate JSON fields. `ArtifactShellSigner` obtains only the
selected attestation key; its GCP key provider excludes custody key roles. The
constructor returns the signer handle for later selection replacement. The
shell has no app database registry or filesystem mounts. App hosts retain their
own `ArtifactApprovalAuthority`, custody keys and attestation verification key.
The native `IapWorkload` selects the dedicated `oauth_shell_transport` service
account and the exact `/_day2/oauth/approval` URLs of selected apps. It acquires
an explicit GKE metadata access token for each IAM Credentials `signJwt` call.
The returned JWT must preserve the selected issuer, subject, exact protected URL
audience and five-minute lifetime. Unknown apps, origins or paths are refused
before acquiring credentials. No service-account key, ADC, proxy, redirect or
browser token participates. The control plane's app-query gates reuse this same
native signing adapter with their separate URL allowlist. See [Google's IAP
service-account authentication](https://docs.cloud.google.com/iap/docs/authentication-howto).

## App host startup

The native provider host supplies a `ReviewedCatalog` and live
`OutboundReadiness` to `deployment::serve_with_oauth`. Startup admits the actual
active app artifact, initializes the app's ordinary principal and OAuth tables,
and composes its `ArtifactApprovalAuthority`, `StoredAppApprovals` and receiver
on that app's database. It does not load sibling artifacts or custody keys.
The receiver mounts before ordinary human admission and business dispatch,
with the host's bounded concurrency, body deadline and shutdown admission guard.
The shell workload is never issued an app human session. The OAuth route prefix
is reserved even when no receiver is selected.

The ordinary `day2-serve` entry point still refuses nonempty OAuth selections.
The native Google composition is available, but its live fact source, canary
workload and renewal path still need to be wired into the qualified launcher.
Missing provider code or readiness cannot
be enabled through an instance boolean, a CLI flag or merely configuring keys.
Static startup qualification still does not establish external readiness;
every approval lookup and settlement retains its current readiness checks.

Requests and responses have fixed versioned JSON schemas, bounded bodies and
deadlines. Receivers reject unknown or duplicate fields, wrong paths, methods,
Host headers, audiences and namespaces. The client disables proxies and
redirects and sends confirmation once. Response loss is ambiguous; it does not
trigger an automatic retry. A subsequent lookup observes durable settlement,
and replay cannot activate the same attempt twice.

## Reviewed Google Calendar registration

The native `oauth/google.rs` catalog publishes `google_calendar_mapped_v1` and
`google_calendar_external_v1`: confidential S256 browser-code profiles with
reusable refresh and no automatic retry. Installation-owned access is not reviewed.
The catalog derives identity scopes and Calendar `events.readonly`/`events`
scopes from the admitted declaration's `list_events`/`create_event` actions.
Only Google's `email` identity-scope alias is normalized; missing, duplicate or
broader scopes fail. Publishing this protocol profile does not publish Calendar
business operations or generated Roc functions. The Calendar write scope also
permits provider operations beyond creation; native dispatch must still enforce
the selected semantic action. See [Google's scope definitions](https://developers.google.com/workspace/calendar/api/auth).

`registration::Target` derives the exact callback from the qualified instance
security origin, reviewed profile and complete binding namespace. Its setup
description contains only the client ID, callback, exact scopes and credential
reference. That credential reference binds the installation, client ID and exact
numeric Secret Manager project/secret/version. Client secrets reuse the bounded,
checksum-checked approval-key transport without being interpreted as custody
keys. No ADC, proxy, redirect, secret alias or app token chooses the source.

The private `ops/OAuthRegistration.roc` campaign orders these native operations:

1. Read the exact selected client-secret version.
2. Require Google to reject one code with the wrong S256 verifier, then accept
   that same code with the correct verifier. A generic invalid-code rejection
   alone is insufficient. Require rejection of a separate code sent without
   the required client credential.
3. Exchange a third code using the selected client, exact callback and verifier.
4. Fetch UserInfo with that access token; require the explicitly selected stable
   Google `sub`, verified email and hosted-domain `hd`. Email is presentation.
5. Refresh once, require exact scopes and reusable-token behavior, then verify
   the same subject and tenant again using the refreshed access token.
6. Re-read the exact secret version before sealing the native readiness receipt.

Each code comes from a distinct one-use `Authorization`, with cryptographic
state/verifier, an S256 challenge, fixed provider URL, exact callback and a native
shell-session binding. Callback parsing rejects duplicate parameters, wrong
state/issuer/session and expiry. Recipe arguments cannot choose any credential,
code, endpoint or callback. Acceptance of a negative probe, an unrelated failure,
response loss or a transport error cannot qualify the registration. Every step
is fenced before I/O; failure closes the session and requires a new canary. The
S256 correction is an explicit conformance obligation, never an automatic
product exchange retry. A provider that invalidates codes on verifier rejection
cannot pass this conservative campaign.

Receipts are not serializable and expire after five minutes using wall and
monotonic clocks. The registration revision remains stable across identical
renewed probes. Tokens, codes, verifiers, secrets and provider error descriptions
never enter recipe responses or receipts. Every host starts with an empty
receipt registry. Desired JSON, restored state, simulator output and an
operator-authored digest cannot create a live receipt.

`GoogleReadiness` checks the selected registration, profile, requirement,
generation and security shell before consulting the independent live
`OutboundReadiness` source. That source must still establish shell, custody and
account-mapping/approval readiness for the exact owner. `Providers::google`
combines this gate with the reviewed catalog. A Google probe does not qualify
those other services. The host must arrange renewal before expiry; this slice
introduces neither a background renewal loop nor an app refresh job.

Canary credentials must be isolated from active product grants. Google remote
revocation can invalidate an account/client grant; the campaign performs no
automatic revocation or successor cleanup. See [Google's OAuth lifecycle](https://developers.google.com/identity/protocols/oauth2/web-server)
and [stable identity claims](https://developers.google.com/identity/openid-connect/reference).

### Creating a company web client

Create a Google Auth Platform **Web application** client in the installation's
GCP project, with the appropriate consent-screen audience and an explicitly
permitted canary account. This is the Google API/OIDC client, not an IAM workforce
OAuth client or an IAP backend client. Save the client ID and exact Secret Manager
reference in the instance repo; store the raw secret in Secret Manager without
a trailing newline. Never put secret bytes in a PR, CLI argument, environment
variable or app table. See [Google's client setup instructions](https://developers.google.com/workspace/guides/create-credentials).

The independently selected reauthentication client needs
`<security_shell.origin>/_day2/reauth/callback`. The Calendar registration needs
the exact `Target::description().callback_url`, under
`<security_shell.origin>/_day2/oauth/callback/<derived digest>`. These are separate
protocol roles. Register the derived provider URL only after selecting the app
requirement and complete binding; do not invent the digest or use the product
origin, reauthentication callback or a wildcard. Google requires exact matching.

The native shell launcher must mount the canary callback, verify its own shell
session, collect the three distinct authorizations, run the pinned recipe and
publish its native receipt into that host's registry. The native
`SecurityShell::from_gke_with_registration` constructor now composes those routes
from one admitted instance snapshot, live shell evidence, the pinned recipe
runner and a native `GoogleReadiness` registry. The launcher supplies that live
evidence; desired JSON cannot provide it.

Only the explicitly selected canary IAP subject may open
`/_day2/oauth/qualification/<registration ID>`. Its tenant must equal the shell's
verified installation tenant. The page shows the exact callback, scopes, client
and secret-version reference and the desired registration pin; those setup
values do not assert readiness. A same-origin CSRF-protected POST starts three
distinct Google authorizations. The digest-derived provider callback accepts
only the selected route, one-use state, selected human and five-minute shell
cookie. Query data and forms cannot choose a client, credential, verifier or
target. Raw codes and tokens never appear in the page or response.

The final callback runs `ops/OAuthRegistration.roc` once outside the routing
lock. A failed or lost exchange requires a new campaign. Selection replacement
clears browser state and retires the local receipts; a campaign finishing after
retirement cannot publish. Successful completion publishes only to the supplied
native host registry and clears the cookie. A shell process's receipt is not
automatically evidence for a separate app-host process; trusted live readiness
distribution still needs composition. Renewal and workload deployment remain
runtime work. The real HTTP fixtures exercise the
same native campaign and Roc recipe but cannot qualify a Google client.

## Remaining runtime work

The next runtime slice must supply independently live shell/custody/account facts,
start the separately qualified shell workload, distribute registration readiness
to app hosts and wire connect attempt creation. The real Google web clients and
their exact secret versions remain required; their instance contract and native
exact-version loader are available. The edge contract now
publishes a dedicated keyless signer and supports backend access; these plans
must still be applied and their live workload/secret policies qualified.
App-host IAM separately needs its custody and verification keys.

This layer does not start a shell workload, create a Google web client, establish
live installation readiness or enable OAuth on an installation. Live registration
qualification requires the real client and deployed canary callback. Calendar
business dispatch and the connect/use/refresh canary remain follow-up work.
