# Canonical identity selectors

The Instance owns desired credential and external security epoch selection.
These wire contracts contain resource names, immutable versions, role and
namespace bindings. They carry no key bytes, observed epoch, subject mapping or
current readiness. The native custody and epoch adapters are separate changes.

`Instance::security_key_set` covers the app's selected credential verifier,
issuer encryption and dedicated shell attestation, OAuth custody and shell
attestation, provider clients and reauthentication client. It includes every
named selection, binding revision, exact provider version and namespace
generation. Repeated OAuth selections deduplicate a key while retaining all
selection names. Different purposes cannot share a secret container, including
different versions of that container.

The installation control catalog must select one scoped external authority per
app with actual credential/OAuth bindings or a selected scoped runtime, pins its
complete selector and rejects duplicate immutable database/scope identities.
A missing whole credential runtime catalog refuses when credential families
are declared; present catalogs must exactly cover the selected apps and families.
Declared OAuth connections also require complete app/account runtime selection;
removing that catalog refuses even when the scoped epoch selector remains intact.
An ordinary security-free app needs neither runtime nor authority selection.
Provider-free Instance admission checks quota,
management identity, dedicated shell, attestation and key selectors. An empty
OAuth app catalog may retain shared shell metadata only alongside a complete
credential selection; standalone OAuth catalogs remain nonempty.
Issue, rotate and revoke keep the supported Creator policy and creator-reveal
delivery. Metadata reads retain the existing closed Creator/MemberOf predicate;
desired group selection alone supplies no membership or live authority proof.

Backups preserve scoped historical catalogs and their exact keys. The restore
digest binds the verified snapshot identity; it provides no current authority.
Ordinary disabled restore refuses selected credentials, OAuth or an external
epoch before creating output. Target-app runtime selections count even if
binding metadata was stripped; foreign-app-only runtimes do not secure the
target. It also checks the admitted artifact's credential and OAuth declarations
so removing metadata from a current snapshot cannot bypass refusal.
Ordinary apps retain the existing isolated, disabled
restore behavior. A future native security restore must obtain CURRENT and live
fencing evidence independently of the backup.

This source-only slice is composed on accepted PR124 main `c4aa7a2` (tree
`83249b384ce7eb86c9c62212782785607335e19e`). It requires no new
dependency, native epoch module, provider adapter, host route, provider resource
or restore executable. Two pure capability sources are explicitly registered;
architecture AST inventory, native formatting, compiler checks, focused tests
and the full gate are **UNRUN for this exact new source**. No A native receipt
qualifies B. No source
ratchet fingerprint or seal was regenerated without native evidence.

The installation adapter's adoption of these canonical desired calculations
remains a separate implementation step using `Instance::validate_credential_runtime_metadata`,
`credential_identity_revision` and `credential_shell_revision`. Native role,
freshness, proof and subject checks remain in that adapter. The client fixtures
and credential-only shared-shell admission already use these canonical methods.

The app deployment copies operator-selected current epoch metadata unchanged
from the complete `oauth_instance_json`. There is no new variable, provider
resource, IAM grant or current-epoch producer. Terraform checks finite scope,
UID/digest shapes and the existing 1..60 second selection bound; native Instance
admission checks the complete key-set digest against actual serde struct bytes.
The plan oracle's UID and digest are synthetic desired DATA, not observations
of a live database or readiness. All new native and OpenTofu controls are unrun.
The shell plan fixture now supplies the same complete current desired contract,
preserving its shell identity, bounds and secret roles. Its native closed-loader
control checks the exact typed key-set digest; its UID and pins remain test DATA.

The private read-only OAuth setup entrance decodes bounded duplicate-free JSON
into closed desired DATA, re-pins only an existing unique exact scoped selector's
key-set digest and combined families' epoch revision, and requires full Instance
admission before preparing final artifact-owned bindings. It repeats complete
key selection and strict admission afterwards. The explicit alias, scope,
provider, UID, IAM and lease stay unchanged; wrong family aliases refuse. Raw
fields are preserved for the full loader's refusals. Serving and runtime loading
keep strict admission and cannot normalize desired pins. These hashes never
supply a current epoch, key custody or readiness proof.

Ordinary printed-link development creation refuses actual credential manifests
before creating output. `create_verification_for` explicitly authors complete
disposable desired DATA, then shares the ordinary strict loader/initializer;
Build campaigns use that entrance without skipping credential artifacts. The
existing simulated verification authority is installed separately. A narrowly
scoped `repin_credential_verification_data` checks the actual artifact and exact
manifest/runtime/epoch coverage before updating desired revisions after final
context changes. It preserves business predicates, approved roots and selected
providers, aliases, UID, IAM and lease; it creates no missing selection or native
authority. The metadata HTTP fixture uses real test-held IAP signatures through
the existing verifier/session path, preserving unsigned refusal, Bob's principal,
forged-header/actor-query refusal and metadata privacy controls. It has no Google
keys or live provider/browser qualification.
Current-only changes replace callers in place and add no compatibility route,
schema migration or staged cutover.
