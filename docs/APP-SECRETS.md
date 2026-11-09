# Owner-managed app secret storage

Protocol 2 exposes `GET /api/app-secrets`,
`GET /api/app-secrets/requests/REQUEST_ID` and `POST /api/app-secrets` on the app
origin. `POST /api/app-secrets/reveal` returns the selected exact version as
uncached binary bytes. The Rust Day 2 CLI uses these endpoints after company login. Requests
use the existing IAP/app session; this surface has no machine credential,
impersonation or local-operator authentication fallback.

Active owners have `secrets.list`, `secrets.create`, `secrets.rotate`,
`secrets.read` and `secrets.delete`.
Every admission and subsequent provider dispatch rechecks the active authority,
installation/app scope and activated namespace. App users and installation
operators without active ownership are denied. POST requires the exact origin,
CSRF token, `Content-Type: application/json` and a bounded `Idempotency-Key`.

## Instance configuration

Add an operator-selected namespace to the app binding, then activate that same
document through the existing authority workflow:

```json
{
  "managed_secrets": {
    "project_number": 123456789,
    "access_token_file": "/run/private/app-secret-token"
  }
}
```

The token file must be a regular private file with no group/other access, at
most 8,192 bytes, and one hard link. The adapter opens it with NOFOLLOW/NONBLOCK
and checks the opened descriptor against the inspected file. Operators inject
and refresh the bearer token explicitly. The adapter does not discover ADC,
environment tokens, metadata credentials or `gcloud`. Parent-directory trust
and secure erasure of all transport allocations are not established here.

Use project-scoped IAM limited to the reviewed app resources and required
Secret Manager operations. Namespace configuration is authority, not app-owned
data. A changed desired namespace stops operations until explicit activation.
The physical name is `day2-<32 hex scope digest>-<32 hex incarnation>`; the
incarnation binds scope, logical name and the original creation request. The scope
contains installation, environment and app. Labels bind the provider container
to the exact scope and original create request. Existing secrets are not adopted.
Control/bootstrap secret containers cannot overlap these namespaces.

### GKE exclusive workload

The `day2-app` deployment root accepts an explicit `managed_secrets` selection:

```hcl
managed_secrets = {
  project_number    = 123456789012
  token_secret_name = "app-secret-provider-token"
}
```

An operator creates that Kubernetes Secret in the app namespace with a private
`access-token` key. Supply its bytes from a private file using the installation's
credential process; never put the value in Terraform variables, a plan, source,
command-line arguments or output. Terraform references the existing name only.
The selected provider identity must have only the reviewed Secret Manager access.

At pod start, a digest-pinned init container copies the selected key to a regular
UID/GID 10001 file with mode 0600 in a dedicated memory-backed volume. The app
host mounts that volume read-only. It never mounts the Kubernetes source Secret;
companions and backup jobs receive neither volume. The pod keeps API-token
automount disabled. An absent selection adds no namespace, material mount or
init container. Selecting a namespace does not activate authority on existing
app data.

This is explicit operator delivery, not an automatic token issuer: update the
existing Kubernetes Secret and recreate the exclusive pod before bearer expiry.
Running pods keep their startup copy. Provider rejection or expiry fails closed
without token discovery or write retries. Rolling, release-managed and native
enrollment workloads are refused until their material-release path is qualified.

Metadata schema 2 is installed only during fresh app initialization. Existing
databases without it fail closed. Do not erase GoLinks links or perform an
implicit migration to enable this feature. Backup restore clears desired
namespace selection along with the existing authority fences.

## Writes and recovery

POST accepts exactly `operation` (`create`, `rotate` or `delete`), `name`,
`expected_authority`, `expected_version` and `expected_incarnation`. Create and
rotate also require base64 `value`; delete refuses a value. Names are 1–40 ASCII
letters/digits/underscores/hyphens, starting with a letter or digit. Values contain
1–65,536 bytes. Create requires a new logical name; rotate requires the listed
stored incarnation and version, or null for an already-created empty container. Authority and
version comparisons happen atomically before provider I/O.

Create stores a new container and its first version. Rotate adds a new version
containing supplied bytes. Neither operation changes app bindings, activates a
release, generates provider credentials or revokes upstream keys. The receipt
has `activation_performed: false`; a stored value is not proof of runtime use.

Native admission persists metadata before dispatch, then settles the observed
outcome without holding an SQLite transaction across the network call. Roc owns
step ordering in `ops/AppSecrets.roc`. `xtask app-secrets-table` exports the pure
decision table embedded in deployed runtimes. Runtime source-digest checks and
a native test against the compiled Roc runner reject stale/different tables.
The deployed endpoint requires neither a source checkout nor a workflow process.

The provider uses bounded HTTPS, fixed origin, no redirects/proxies/retries,
CRC32C payload verification and exact resource/label/version validation. Lost
acknowledgements or malformed success responses are `unknown`. Receipts and the
append-only audit contain actor, authority, request, scope, step and stored
version; values, secret-derived hashes, CRCs and raw provider errors stay out.

Each submission uses a new request ID. Reusing any admitted ID is refused,
including the same bytes. Inspect the original request with GET rather than
resubmitting its value. Unknown or interrupted writes block further writes to
that name. Explicit reconciliation is future work; process restart never
automatically repeats a provider write. A revoked owner cannot dispatch another
step or retrieve the outcome, although already dispatched results are recorded.

Reveal admits a unique request ID and selected current incarnation/version under
`secrets.read`, checks the exact provider resource, original creation label and
CRC32C, then rechecks current ownership, authority and selection before returning
bytes. Values remain outside receipts/audits. The response is
`application/octet-stream`, `Cache-Control: no-store`, with base64 metadata in
`X-Day2-Result`; it never includes a value in JSON.

Delete requires `secrets.delete` and matching authority, incarnation and version.
The adapter verifies exact scope/original-create labels, reads the current ETag,
and sends one conditional delete. Admission, dispatch and outcome are audited;
uncertain outcomes block further writes. A confirmed deletion leaves a tombstone
and removes the entry from listing. Recreating the same logical name uses a new
physical resource, preventing old immutable version references from aliasing new
bytes. The provider identity needs scoped `secretmanager.versions.access` and
`secretmanager.secrets.delete`, in addition to the creation/rotation permissions.
Neither operation changes running bindings or revokes upstream API credentials.
Consumer-aware activation/retirement remains separate work.

`GET/POST /api/app-sqlite` uses the same human session and POST Origin/CSRF guards
under `sqlite.download`. It exports a fresh, bounded database containing admitted
business tables only; see [APP-SQLITE.md](APP-SQLITE.md).

## Verification

Focused native tests cover ownership, desired/active drift, authority/version
conflicts, unknown outcomes, revocation between steps, journal privacy and HTTP
Origin/CSRF/session boundaries. Loopback tests exercise the real provider adapter
and its resource/CRC/response/token-file validation.

An explicitly ignored live integration test runs `app-secret-canary` from the
same Roc recipe. Supply a private `DAY2_APP_SECRET_LIVE_PROFILE` containing
`project_number`, `access_token_file`, `apps` (at most eight names) and
`allow_create_rotate_read_and_delete_test_secrets: true`, plus
`DAY2_TEST_OWNED_PROBE_ARTIFACT`. Run:

```console
bazel run //crates/xtask:xtask -- workflows
bazel run //crates/xtask:xtask -- test-rust //crates/day2:day2_integration app_secret_live --ignored --nocapture
```

Each scope gets a fresh random canary installation and synthetic secret; no
hosted app database or running secret binding changes. The test verifies both
versions, deletes only resources with this run's exact scope/request labels and
current ETag, and confirms 404. Failure unwinding attempts the same guarded
cleanup and prints any resource still requiring cleanup. No CI credential or
company project default is embedded. This qualifies only the tested native
provider/storage path, not hosted IAP, OS credential storage or app activation.
