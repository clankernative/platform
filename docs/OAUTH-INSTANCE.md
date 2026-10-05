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

### Reviewed provider extensions and version 2 clients

`oauth/catalog.rs` composes the reviewed provider profiles independently of the
protocol kernels. Declaration admission asks this registry for semantic access;
the app SDK publishes each capability explicitly. Native host startup, setup,
registration qualification, publication and readiness use the same catalog.
Publishing a provider does not select it for any company or mint readiness.
Only `apps[app].oauth_connections` selects profiles for that company's declared
requirements. The client and runtime account catalogs supply the corresponding
registration and account ceilings. Unselected requirements remain inactive.

Version 1 retains its exact Google shape and evidence pins. Version 2 requires
tagged provider clients and independently named qualification/provider accounts:

```json
"oauth_clients": {
  "version": 2,
  "reauthentication": {
    "client_id": "123-reauth.apps.googleusercontent.com",
    "credential": "google_reauth_client"
  },
  "registrations": {
    "projects_registration": {
      "client": {
        "kind": "gitlab",
        "client_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "credential": "gitlab_client"
      },
      "canary": {
        "qualification_subject": "accounts.google.com:112233",
        "provider_subject": "42",
        "provider_tenant": "gitlab.com"
      }
    }
  }
}
```

The existing `oauth_runtime.apps[app].accounts[requirement]` selects
`external_accounts`, with `allowed_tenants: ["gitlab.com"]` and an optional
nonempty ceiling of canonical numeric GitLab subject IDs. The app declares
`GitlabProjects.read_projects` and `explicit_external_account`; the binding
selects `gitlab_projects_external_v1`. Setup derives current revisions from the
actual admitted declaration. Missing clients, provider/profile mismatches,
unsupported owner/account combinations, unknown kinds or versions, mixed v1/v2
shapes, inline credentials, authored endpoints/scopes and key-role substitutions
fail admission. Different companies choose clients, exact secret references and
account ceilings in their ordinary instance documents without kernel changes.

GitLab.com is a second actual native registration adapter, with rotating refresh
and mandatory reauthorization after uncertainty. Its fixed token-info endpoint
establishes exact scopes, client ID and resource owner even when the token
response omits scope. Its account endpoint verifies the numeric, active,
unlocked subject. Email/display fields cannot map it to the shell human. The
selected shell human authorizes the canary campaign independently. These wire
contracts follow [GitLab's OAuth API](https://docs.gitlab.com/api/oauth2/) and
[current-user API](https://docs.gitlab.com/api/users/#retrieve-the-current-user).
`read_api` also permits other REST reads at GitLab; the future native business
dispatcher must enforce the declared `list_projects` action. This slice publishes
registration qualification and semantic intent, without granting app API dispatch.

Adding a reviewed provider means adding its native adapter/profile and semantic
SDK contract when needed, explicitly registering them, and supplying runnable
deterministic and HTTP conformance drivers for every published tuple. No
connection, callback, exchange, custody, refresh-store or account-approval kernel
changes are needed for this second provider. Company customization of endpoints
or different protocols requires a new reviewed, pinned profile and its drivers;
configuration cannot upload arbitrary code or assert conformance/readiness.

The reviewed extension workflow is:

1. Define semantic intent in the explicit SDK catalog if the capability is new.
   Keep client IDs, URLs and provider scopes out of app declarations.
   Seal helpers that call restricted constructors and pin their reviewed bytes.
2. Add a native profile with pinned endpoints, exact semantic scope interpretation,
   account evidence, refresh behavior and a recovery policy. Add its closed client
   selection and native registry dispatch; unsupported combinations must fail.
3. Implement wire parsing and I/O through the shared OAuth effects boundary.
   Provider observations cannot manufacture account approval or live readiness.
   Catalog new native sources in `architecture-rules.json` and pass
   `xtask architecture-check`; new adapters do not gain ambient effect access.
4. Add independent deterministic obligations, every relevant fault boundary and
   exact replay, plus native HTTP conformance. Register every published
   profile/adapter/simulator/conformance tuple and its compiled source identity.
5. Build a real app declaration canary through `ops/Verify.roc`, exercise ordinary
   instance setup/admission, and pass the full gate. Companies then select that
   reviewed profile and their own clients, secrets and account ceilings.

The selected GKE security shell still uses Google IAP and Google fresh
reauthentication. That infrastructure identity adapter is separate from outbound
provider selection. This change does not implement GitLab API execution through
the future typed `Use` API, qualify a live client, deploy either provider, or
support arbitrary self-managed GitLab origins. Native live qualification remains
required for each exact client, callback, profile and instance selection.

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

The ordinary `day2-serve INSTANCE APP --edge` entry point now composes the reviewed
provider host when the installation selects `oauth_runtime`. This happens after
kernel, artifact and current authority admission. A nonempty OAuth selection
without that typed catalog or an explicitly supplied native provider still fails
startup. The canary workload and renewal path require their separate launcher.
Missing provider code or readiness cannot
be enabled through an instance boolean, a CLI flag or merely configuring keys.
Static startup qualification still does not establish external readiness;
every approval lookup and settlement retains its current readiness checks.
Issuer identifiers retain their exact reviewed spelling, including Google's
`https://accounts.google.com` value without a trailing slash. URL parsing may
add a slash internally, but pins and comparisons never normalize that protocol
identifier. Authorization, token and callback endpoints remain canonical URLs.
See [Google's OpenID Connect contract](https://developers.google.com/identity/openid-connect/openid-connect).

### Independent native facts

`oauth_runtime` is a shared `day2-capabilities` instance contract. Keep it in the
company's instance repository alongside `security_shell`, `oauth_clients`, and
the existing exact-version secret catalog. It contains no URL, credentials,
qualification digest, receipt, or readiness boolean. For example:

```json
{
  "version": 1,
  "shell": {
    "project": "company-tools",
    "backend_service": "selected-gke-shell-backend",
    "url_map": "selected-gke-shell-url-map",
    "https_proxy": "selected-gke-shell-https-proxy",
    "forwarding_rule": "selected-gke-shell-https-forwarding-rule",
    "kubernetes_service": "tools/security-shell"
  },
  "apps": {
    "workspace": {
      "service_account": "app@company-tools.iam.gserviceaccount.com",
      "accounts": {
        "calendar": {
          "kind": "external_accounts",
          "allowed_tenants": ["example.com"],
          "allowed_subjects": null
        }
      }
    }
  }
}
```

`accounts` keys are the app's declared connection registration names. Every
selected connection must have exactly one policy matching its admitted
requirement. `external_accounts` supplies a nonempty tenant ceiling and an
optional nonempty immutable-subject ceiling for the existing fresh external
approval flow. `iap_subject` selects the reviewed Google IAP subject mapping for
a mapped-human requirement. It does not create a mapped connect attempt; that
dispatch remains follow-up work. Installation Google accounts are not reviewed.

Run `day2 oauth-setup INSTANCE` after selecting these resource names and real
Google clients. This read-only command admits selected artifacts and emits
desired shell, account-mapping, attestation and registration pins, connection
bindings, and exact callback URLs. Review and save the emitted bindings in the
instance repository. It does not write files, contact Google, retrieve secrets,
or issue readiness. Changing the shell selection changes its native profile
revision and dependent callback/attestation/registration pins.

Setup accepts syntactically valid desired bindings whose derived revisions are
initial or stale. It admits the selected artifact bytes, finds each registered
requirement, and derives the requirement, reviewed Google profile, custody,
security origin, account mapping, attestation and registration revisions before
performing strict qualification. The selected profile **ID** must still match
the app's declared account policy. Installation/environment/app scope, binding
generation, registration ID, secret names and numeric versions, key binding IDs,
and approved product-return selection remain operator selections. A missing
declaration, wrong profile ID, unknown JSON field or overlapping secret role
fails setup. Serving constructors always require exact derived pins.

The output includes an `instance` document with the recomputed bindings and
all other selections preserved. Review it before saving it as the installation
snapshot. Running setup against that snapshot is idempotent. Recompute and
register the exact callback after any selection change; the old callback must
never stand in for the new binding. Client IDs and their exact secret references
are needed to derive it; no placeholder ID establishes a real registration.

[`fixtures/oauth-calendar-canary`](../fixtures/oauth-calendar-canary/README.md)
provides a complete, minimal registration target. It declares company-account
Calendar event reads and exposes only an intent-inspection query. Its native
build and SQLite/setup checks are part of the full verification campaign; they
do not perform the Google sandbox campaign or Calendar business dispatch.

The fact source starts empty. A current verified human must first match the
pending attempt's owner and the app database's immutable IAP subject binding.
Only then can the host obtain a native owner lease, valid for at most 120
seconds by both wall and monotonic clocks. Restoring a principal row cannot
create that lease. Every facts lookup rechecks the durable subject binding;
the preview also continues to bind the immutable subject.

For each selected connection, a native facts lease lasts at most 60 seconds
from the start of its checks, using both clocks. Failed renewal removes the old
lease. The host reads the selected Compute project, backend and URL map through
the fixed Google API endpoint. It checks the numeric project/backend identity
against the selected IAP audience, enabled IAP, the GKE namespace/service
description, and an isolated exact-host URL map whose default and every path
route select that backend. Wildcard hosts, redirects, header overrides and
advanced routing shapes are refused. The HTTPS proxy must select that map and
the global TCP/443 forwarding rule must select that proxy. The TLS connection's
actual peer IP must match the forwarding rule's address. Backend, URL map,
proxy and forwarding rule reads must agree again after the TLS probe. These checks use the
[Compute backend service](https://docs.cloud.google.com/compute/docs/reference/rest/v1/backendServices)
and [URL map](https://docs.cloud.google.com/compute/docs/reference/rest/v1/urlMaps)
contracts, together with the
[HTTPS proxy](https://docs.cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies)
and [global forwarding rule](https://docs.cloud.google.com/compute/docs/reference/rest/v1/globalForwardingRules).

The TLS probe uses the selected `security_shell.origin`, system certificate
roots, no credentials and no redirects. An IAP login or denial can establish
TLS reachability; this probe does not establish shell process health or check
every DNS answer. Shell workload admission and least-privilege IAM policy still require
deployment qualification. A successful secret read proves availability to the
running workload, not that its IAM policy has no other grants.

Each facts renewal reads all three selected numeric key versions and checks
their actual binding, version and purpose. Approval additionally retrieves its
three key leases on every lookup and rechecks readiness after retrieval. Every
cloud token request first verifies the selected app service-account email at
the fixed metadata endpoint, following Google's
[metadata contract](https://docs.cloud.google.com/compute/docs/metadata/predefined-metadata-keys).
No ADC, environment-selected credentials or process credential file is used.
The app workload also needs read access for the selected Compute project,
backend, URL map, HTTPS proxy and global forwarding rule. Keep these read
permissions and named-secret access in the instance's reviewed IAM deployment;
the host neither adds grants nor falls back to operator credentials.

Runtime selection changes fail closed against the fact source's pinned catalog.
Restart the app host to compose a new fact source after changing that catalog;
native receipts and facts are never persisted or carried into the restart.
The native source supplies expected registration metadata only behind the
existing `ProviderReadiness` gate: a signed fresh live canary publication remains
required independently.

### Dedicated shell launcher

`day2-security-shell INSTANCE` starts a separate stateless Linux listener on
port 8080. Its only argument is the instance path. The selected
`oauth_runtime.shell_resources` supplies the existing shared resource bounds:

```json
"shell_resources": {
  "memory_mib": 512,
  "cpu_millis": 500,
  "process_limit": 1024,
  "process_limit_enforced_by": "pod",
  "http_concurrency": 4,
  "shutdown_seconds": 30
}
```

These are deployment bounds, not readiness evidence. The optional field keeps
older app-host catalogs compatible; the dedicated launcher requires it. The
launcher checks the private cgroup-v2 limits, regular instance and addressed
artifact paths, read-only installation and workflow mounts, admitted artifacts,
exact selected registration pins and the pinned native Roc recipe runner before
binding HTTP. It opens no app database and creates no app runtime or principal
session. A writable mount anywhere beneath the installation, including an app
state directory, prevents startup. The GKE pod PID bound is still an operator
declaration until separately observed on the actual node pool.

The shell selects `oauth_shell_transport.service_account` for every metadata
token request, including edge reads, keyless IAM signing, client-secret reads
and attestation-key reads. Each token acquisition first checks the actual
metadata service-account email. App custody keys are absent from the shell key
provider. Its client catalog must exactly cover the admitted selected registrations.
The client/attestation selections must also be disjoint from custody
**secret containers**, even at different versions: this reviewed edge uses
unconditional secret-level grants, which cover every version in that container.
Version-specific IAM conditions are not part of this profile. See [Google's Secret Manager access control](https://docs.cloud.google.com/secret-manager/docs/access-control).

Desired target pins are assembled at startup with an empty native registration
registry. After IAP human verification, every OAuth dispatch requires the
independent native edge guard. Its empty-at-start lease checks the same selected
Compute resources and actual TLS peer as the app source and expires after at
most 60 seconds by both clocks. Failed renewal discards the old lease. The final
canary callback checks that guard again after provider probes and before signing
and publishing the receipt. The shell registry supplies no app readiness facts;
the destination app independently verifies publication and live facts.

Browser responses use `Referrer-Policy: strict-origin`: HTTPS form submissions
retain their exact Origin, while referrers omit paths and callback queries.
`no-referrer` would make a navigation POST send `Origin: null`, which the shell
refuses. Every form remains restricted by `form-action 'self'`. For a native
absolute HTTPS 303 destination, the HTTP layer returns a no-store HTML handoff
with an escaped refresh target and Continue link; navigation starts from that
document. This supports Google authorization and owning-app returns without
allowing off-origin form targets. Relative 303 responses and native workflow
protocols are unchanged. The HTTP regression checks cover these response and
request envelopes; a live browser campaign is still required for qualification.

`/health/live` and `/health/ready` are bounded, unauthenticated process probes with
no-store responses. Readiness reports completed static startup admission and
whether the listener accepts work; it does not report Google registration,
secret availability or installation qualification. Keeping probes separate from
external checks lets an unqualified installation start its listener and run the
explicit authenticated qualification flow. See [Kubernetes probe semantics](https://kubernetes.io/docs/concepts/workloads/pods/probes/).

HTTP admission rejects excess concurrency, bounds bodies to 4096 bytes and body
waits to three seconds. Capacity remains held through an unabortable native
operation even after browser disconnect. SIGTERM stops admission first, makes
readiness fail, and drains HTTP plus outstanding native dispatch within the
selected grace. Restart loses shell sessions, canary attempts and local receipts;
it cannot restore readiness. No automatic campaign retry or renewal is added.

The [security-shell deployment root](../deploy/gke/stacks/security-shell/main.tf)
consumes the existing installation edge contract. It checks the exact origin,
numeric IAP audience, dedicated workload identity, namespace/service and declared
secret-container grants against the instance. The root rejects missing edge
resolution, extra secret grants, custody-container sharing and floating images.
It creates one Deployment with Recreate strategy, non-root execution, a read-only
root, no host privileges, no mounted service-account token and no app PVC or
secret volume. Only the regular read-only instance and bounded temporary scratch
are mounted. The image contains the selected admitted Linux artifacts and pinned
workflow distribution; callbacks and company domains continue to come from the
instance's existing edges.

The edge root adds a custom role containing only `resourcemanager.projects.get`
and four Compute reads: backend services, URL maps, HTTPS proxies and forwarding
rules. Resource Manager supplies the project number for the IAP audience;
Compute's project `id` is a separate resource identifier and cannot supply it.
The native guard checks the selected project ID and active lifecycle state before
comparing the audience. Confirm `cloudresourcemanager.googleapis.com` is enabled
in that project before rolling out these hosts; a permission grant alone does
not enable the API. This planned grant and the published secret list are
desired policy, not an audit of all effective inherited IAM grants. Actual
workload, frontend, namespace isolation and least-privilege policy qualification
remain necessary before claiming installation readiness.

The same reserved channel also accepts native registration publications. A
publication is signed with the exact selected shell-attestation key and carries
the source canary's qualification time and original five-minute expiry. The app
independently verifies the shell workload and forwarded canary human assertion,
the selected immutable canary subject, full current binding, admitted requirement,
client credential revision, shell origin and signature. It loads only the
attestation key for this import. The native canary receipt itself remains
non-serializable; parsing publication JSON cannot populate readiness.

`Providers::reviewed` mounts this receiver on the same app authority and native
`ProviderReadiness` registry used by approval lookup. Selection replacement holds
the same authority lock as import and settlement. Changed or removed bindings
refuse old publications before key acquisition. Registration evidence augments
the independent live shell/custody/account source; a successful import cannot
turn missing facts into approval authority.

The destination retains only the source's remaining wall/monotonic lease. A
duplicate or older publication cannot extend an existing receipt, and expiry is
checked again after key acquisition and independent fact resolution. A restarted
host starts empty; an authenticated republication must still pass the original
absolute expiry. These bounds depend on the hosts' trustworthy wall clocks.
Neither proofs nor receipts are restored from desired configuration or app data.
Publications carry no provider code, token, verifier, key bytes or browser cookie.

Approval also re-resolves the same live facts after acquiring its three keys.
Readiness that expires, disappears or changes during those reads cannot reach
the local settlement callback. External calls finish before the SQLite transaction.

Requests and responses have fixed versioned JSON schemas, bounded bodies and
deadlines. Receivers reject unknown or duplicate fields, wrong paths, methods,
Host headers, audiences and namespaces. The client disables proxies and
redirects and sends confirmation once. Response loss is ambiguous; it does not
trigger an automatic retry. A subsequent lookup observes durable settlement,
and replay cannot activate the same attempt twice.

## Reviewed Google Calendar registration

The native `oauth/catalog.rs` registry publishes Google's `google_calendar_mapped_v1` and
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

`ProviderReadiness` checks the selected registration, profile, requirement,
generation and security shell before consulting the independent live
`OutboundReadiness` source. The selected GKE source independently checks the
shell edge, custody availability and current owner/policy. `Providers::reviewed`
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
runner and a native `ProviderReadiness` registry. The launcher supplies that live
evidence; desired JSON cannot provide it.

Only the explicitly selected canary IAP subject may open
`/_day2/oauth/qualification/<registration ID>`. A legacy version 1 Google canary
must use the shell's verified installation tenant; version 2 selects the provider
account independently. The page shows the exact callback, scopes, client
and secret-version reference and the desired registration pin; those setup
values do not assert readiness. A same-origin CSRF-protected POST starts three
distinct Google authorizations. The digest-derived provider callback accepts
only the selected route, one-use state, selected human and five-minute shell
cookie. Query data and forms cannot choose a client, credential, verifier or
target. Raw codes and tokens never appear in the page or response.

An authenticated qualification refusal keeps HTTP 403 and reports only a closed
native stage/outcome on a no-store page. Code collection, credential loading,
PKCE rejection/recovery, client authentication, exchange, account identity,
refresh, current shell selection and owning-app publication remain distinct.
Provider HTTP status and a closed error-code classification may be shown.
Provider response bodies, arbitrary error chains, URLs, account values, codes,
verifiers, tokens, credentials and cookies
are never rendered. The native diagnostic survives the Roc workflow's text
transport without retaining the underlying error. The failure page is not a
readiness receipt, and publication response loss remains ambiguous.

The final callback runs `ops/OAuthRegistration.roc` once outside the routing
lock. A failed or lost exchange requires a new campaign. Selection replacement
clears browser state and retires the local receipts; a campaign finishing after
retirement cannot publish. `SecurityShell::from_gke_with_registration` now signs
and sends the native publication to exactly the owning selected app using the
existing keyless IAP transport. Final publication holds the routing and signer
selection locks through its bounded, one-shot request; replacement waits for
publication to finish. The acknowledgement pins the exact publication digest.
Successful acknowledgement publishes the local receipt and clears the cookie.
Response loss is ambiguous: the app may hold the bounded receipt, but the shell
reports failure, consumes the campaign and does not retry. A new canary is needed.
App-side selection retirement independently revokes old readiness immediately;
shell-only retirement does not retract an app's already accepted five-minute lease.
Renewal and workload deployment remain runtime work. The real HTTP fixtures exercise the
same native campaign and Roc recipe but cannot qualify a Google client.

## Remaining runtime work

The dedicated shell launcher and deployment root are now available. The app
deployment also consumes a canonical single-app selection via
`day2-app.oauth_instance_json`, preserving the shared OAuth contracts and exact
secret references. `app-edge.oauth_runtime` supplies the one annotated workload
identity, named custody/attestation container grants and the native guard's five
Compute reads; an existing app-call identity is reused. Both roots bind the same
installation shell contract, with company URLs retained in the private instance
repo. See [native OAuth app deployment](../deploy/gke/README.md#native-oauth-app-deployment).
These declarations do not audit all effective inherited IAM privileges.
Use the [installation IAM audit procedure](OAUTH-IAM-AUDIT.md) before reporting
workload isolation; an API selection or successful secret read is not that evidence.

The next runtime slice must qualify the actual deployed frontend/workload/secret
policies and wire connect attempt creation.
Independent app facts and registration publication are now composed in the
ordinary qualified edge launcher. The real Google web clients and
their exact secret versions remain required; their instance contract and native
exact-version loader are available. The edge contract now
publishes a dedicated keyless signer and supports backend access; these plans
must still be applied and their live workload/secret policies qualified.
App-host IAM has a reviewed deployment path for its custody and verification
keys; it must still be applied and qualified on the actual workload.

This layer provides the guarded shell entrypoint; it does not deploy a live workload,
create a Google web client, establish
complete installation readiness or enable OAuth on an installation. Live registration
qualification requires the real client and deployed canary callback. Calendar
business dispatch and the connect/use/refresh canary remain follow-up work.
