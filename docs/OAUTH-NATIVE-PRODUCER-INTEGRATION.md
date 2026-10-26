# OAuth native producer integration

The native integration composes enrollment, original owners, authenticated
first-holder/storage, current writer and actual OAuth consumers. The selected
[S1 connection/request contract](CREDENTIAL-NATIVE-ENROLLMENT.md#admitted-connections-and-fresh-requests)
is being ported in place. Existing native suppliers and earlier tests do not
qualify that new composition or establish a completed live OAuth flow.

## Required suppliers

- G1's authenticated initial-holder peer exchange joins enrolled Controller and
  App messages within their original stages, before the App opens/parses the
  prepared file. It retains the actual message handles, socket, live issuer and
  original intervals. Its native deployment qualification is separate; a first
  holder still cannot substitute for P3/current serving authority.
  Credential owns the fixed issuer entrypoint, operational composition and
  enrollment qualification; G1 owns the real first-holder/storage connection.
- G1 owns provider P3/bootstrap/current-writer/serving implementation, native
  Runtime admission, authenticated peer helpers and the accepted governance contract.
  Product owns final consumer settlement and this integration branch. The current
  `NativeStorageCreationAuthority`, `PreparedInitialFile`, and
  `PreparedFileContinuity` retain real resources, but do not alone authorize serving
  mutations. The native `CurrentBootstrapExecution` constructor requires
  the same retained Controller/file/peer phase and its fixed authenticated
  counter transport; it supplies only the initial bootstrap operations.

`AuthenticatedReads` and `EpochObservation` are read-only observations. A file
projection, successful bootstrap receipt, selected role, or decoded epoch row
must not substitute for an actual supplier. S3's startup
`CurrentPreparedFilePhase` is included: it retains the same file descriptors and
actual Controller stage through a bounded operation, and an abandoned or
refused phase permanently closes continuity. It is physical continuity, not
current writer authority. Full physical/provider admission must finish before
the actual connection lends requests. Later checks use retained handles and
fresh authority/counters rather than repeating that admission.

The stack also includes `InitialStoreMetadata`, which admits instance and
artifact/schema inputs without opening or creating the serving database.
Initial image preparation and App file observation use it instead of a
previously opened `Runtime`. This closes a preparation-ordering gap, but does
not independently construct an authenticated holder or writer owner.

## Producer and continuation boundary

`control.security_bootstraps` is the trusted native startup selection. An app
without a selected policy may serve prerequisite/registration HTTP on the same
fixed executor, but installs no native owner and cannot capture or consume a
production original. OAuth connections and epoch catalog entries alone do not
select native enrollment or establish proof readiness. The canary's deliberate
prerequisite-only selection is an empty bootstrap map.

`Instance::native_bootstrap_for` checks the exact selected app, installation,
environment and unambiguous policy/epoch relationship. A malformed selected
profile refuses startup. A valid selected profile requires real S1 enrollment;
missing operator files, issuer, placement or other enrollment failures remain
fatal. There is no retry or fallback to prerequisite-only operation after a
native failure. App and Shell use the same selection rule.

The final implementation belongs in `oauth/shell_oidc.rs` and the actual
management continuations, rather than returning success from the Google
timestamp comparison. For OAuthConnect and OAuthDisconnect only, it must
consume the exact Google original together with the actual enrolled role,
original lifetime, current storage/holder/writer authority, and purpose-bound
continuation. Returned DATA must not become a transferable permission.

S2's `with_current_original` lends a current `RoleStage` and `OriginalPhase` on
their owning executor. `RoleStage::with_native` lends the actual S1
`EnrolledRoleStage`; its simulation branch cannot supply a native stage. The
S3 consumer must retain those borrows through the actual operation,
including known SQL commit, session creation, signing, provider dispatch and
socket writes as applicable. Each later phase needs current authority, counters,
actual handles and original-clock checks. Admission is not repeated per boundary;
the connection is not reusable permission. A dropped response, unknown commit
or unknown send must retain the
appropriate unresolved ownership; it must not restart either original or
create a second permit journal.

`with_consumer` now retains the same original and role through the real consumer
operation and its result. Pure input or signature refusals are known exclusions
and do not burn another human's valid original. The boundary arms immediately
before the first SQLite open/recovery, commit, signature, session insertion or
provider/socket send as applicable; errors
and unwinding after that point pessimistically retain uncertainty. The
original remains in its owning registry, permanently refused after ambiguity;
there is no timer-based regrant or restoration from SQL. App start, dispatch,
activation and disconnect hold that borrow through the actual SQLite COMMIT
and a subsequent current check. A commit error cannot be swallowed to rearm
the original. Shell session insertion, selected key loading/signing and App
signature verification use the same boundary. Provider token and account
requests retain it through their actual response-body reads.

The Pending/human/runtime SQL facade borrows that same genuine request owner.
Readiness and subject lookups reborrow it, without a nested Current acquisition.
Snapshots/writers cannot escape; each unit closes and postchecks before provider
HTTP. Intermediate units do not finalize the original. The final Pending/human
commit is one-shot: any later SQL unit refuses before opening. Commit, rollback,
close or owner failure poisons the actual request/original even if caught. A
provider permit leaves only after known commit/close/postchecks; an unknown send
retains MayHaveBeenSent and cannot run cleanup SQL after refusal. These remain
mandatory while the connection/request and SQL caller ports are qualified.

The native HTTP socket checks before and after each write/flush/shutdown poll.
Pending and partial writes are not delivery completion. A failed, timed out or
cancelled connection refuses its original; a handler/RPC success cannot erase
that outcome. The App and Shell own their independent response lifetimes.
Successful transport completion means local completion only, not human receipt.

The native consumer now enters S3's sealed `with_current_serving` factory and
holds its `CurrentServingPhase` with the same enrolled stage and original.
Checks, arming and known/excluded/unknown settlement all occur inside that
borrow. An original failure after `finish_known` still refuses the serving
owner before the scope can admit another consumer. Unwinding records terminal
refusal while the real borrow is held, then resumes the original panic.

Socket poll progress and whole response completion have separate serving uses.
Only actual successful HTTP completion selects AppResponseComplete or
ShellResponseComplete. Timeout/disconnect/drop performs terminal refusal in
the existing serving owner without acquiring a new stage or reading a clock.
Completed sockets cannot write or complete again.

The factories require their actual native storage/writer/peer owners;
preparation-only files, snapshots and an epoch boolean cannot fill that role.
The scripted simulator cannot enter the native variant or implement its sealed
trait. Configured native startup refuses if the real suppliers cannot complete.
The selected option-3 source port and live qualification remain owed.

When a storage consumer already holds the native stage,
`OriginalPhase::check_with_native` checks the same retained original through
that exact borrow. It shares the wrapper's clock/refusal implementation. The
caller-supplied wall value is only a floor; current wall time and the retained
enrolled clock are still sampled. It neither reacquires a stage nor authorizes
an operation. Purpose/phase and the actual S3 owner remain mandatory at the
protected consumer.

Approval, CredentialIntent, reveal/ack and all other purposes remain
unsupported. Recurring read and refresh need their own current narrow phase
authority; the human original is not an autonomous grant.

## Verification boundary

Existing signed-Google mounted tests exercise the actual HTTP adapter, real
SQLite and one-use callbacks using test provider keys. They require a forbidden
response without a cookie, session entropy or database mutation even after
valid signed ordering, and retain ambiguous observation delivery and browser
cancellation. These are refusal and adapter controls, not a native producer
success campaign.

The complete selected-profile case must be qualified through the actual owners
and paired with missing, expired, changed-selection and wrong-holder
cases at every protected continuation. No fixture-success factory, boolean
supplier matrix or unimplemented production owner is added here to stand in
for that campaign.

## Storage continuation in progress

The App can consume its checked original file into `AppFileContinuity` while
its original stage is still valid. The same directory/file descriptors and
actual enrollment identity survive; no pathname, projection, old grant or
serialized value can recreate them. Request checks take a fresh
bounded borrow from that same admitted enrollment. The initial-image admission
remains
separate and still rejects modified bytes. Physical continuity alone grants no
first-holder, activation, provider durability or current writer authority.

The Controller's `CurrentPhysicalFilePhase` is distinct from the initial-file
phase accepted by the first-holder exchange. It retains the admitted volume/
provider binding and fresh mount, directory and file identity checks while
allowing SQLite length/content
to change after legitimate writes. Entry closes the parent continuation gate;
abandonment or failure cannot reopen it. Known physical completion is still
not a P3 or current-writer result.

Current database validation checks the canonical original store, seed, marker,
schema, scope and artifact while permitting ordinary App row changes. It
validates DATA only; a caller Connection cannot construct a native owner.

Positive bootstrap/serving requires current storage authority under the accepted
mutator/delegation trust boundary and provider durability contract. The selected
engineering profile is zonal pd-balanced storage with ext4 and the trusted
Controller/node/kernel/CSI/block path. For the current canary instance, the user
accepted the Google-managed Firebase Rules service agent as a
trusted writer/impersonation path, and confirmed Chander, Sebastian and
internal-tools-infra as governance roots. That decision requests no IAM changes;
the earlier v2 IAM proposal remains unapplied. The storage-access, impersonation
and durability decisions are settled. Their connection/request port and native
qualification remain owed. Enrollment, local fsync, previous
readback and an authenticated first holder cannot substitute for current
authority. No selected native factory may open a bypass if admission fails.

For a selected native bootstrap, the launcher checks only desired deployment
metadata and S3's fixed `/state` mount. It never reads an ordinary SQLite
authority row or creates the ordinary replica lock. On the final enrolled App
thread, the real Controller offer is authenticated before opening or parsing
the original file. The completed exchange is consumed into the same executor's
`AppInitialStorageContinuity`, then into `AppStorageBootstrap`. The App drives
S3's six fixed reserve/dispatch/settle steps with a separate fresh stage from
that same enrollment for each step. Only the consuming successful conversion
can install `ActiveAppStorageContinuity` in the executor's registry. An attempt
closes before stage acquisition or channel I/O; failure or panic retains the
same refused owner and cannot restart from SQL, metadata or a second lookup.
A scoped lend of the active owner still needs S3's actual current-serving and
Runtime admission checks. Shell receives no App file or storage authority through this path.

Current App/Controller peer phases require distinct bound request transcripts
from the initial exchange and the last completed phase, signed by the actually
admitted retained peer. They borrow fresh request authority without another
full issuer admission. A new wrapper, nonce or acquisition domain around an old
request grant cannot refresh authority or clear refusal.
This exchange does not supply Shell serving permission; that requires its own
genuine narrow producer without granting Shell storage reader/writer access.

`Runtime::load` now refuses an explicitly selected native bootstrap profile
before inspecting or creating `.state` or opening SQLite. Existing SQL authority
rows cannot recreate the actual current native holder. Ordinary startup cannot
bypass the real consuming Runtime admission factory for that selection.
It does not claim that ordinary apps or explicit synthetic
verification installations have native storage authority.
