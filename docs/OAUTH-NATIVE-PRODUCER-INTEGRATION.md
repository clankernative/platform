# OAuth native producer integration

This branch composes PRs 214 (enrollment), 211 (original owners and HTTP
executors), and 209 (native storage preparation and file continuity). It does
not enable the production fresh-human producer. The authenticated first-holder
exchange is included, but genuine P3/current serving authority is still absent.

## Required suppliers

- G1's authenticated initial-holder peer exchange joins enrolled Controller and
  App messages within their original stages, before the App opens/parses the
  prepared file. It retains the actual message handles, socket, live issuer and
  original intervals. Its native deployment qualification is separate; a first
  holder still cannot substitute for P3/current serving authority.
  Credential owns the fixed issuer entrypoint, operational composition and
  live enrollment qualification; G1 is implementing the exchange against S1.
- G1 owns provider P3/bootstrap/current-writer/serving implementation, native
  Runtime admission, authenticated peer helpers and the accepted governance contract.
  Product owns final consumer settlement and this integration branch. The current
  `NativeStorageCreationAuthority`, `PreparedInitialFile`, and
  `PreparedFileContinuity` retain real resources, but cannot authorize serving
  mutations. `CurrentBootstrapExecution` has no production constructor.

`AuthenticatedReads` and `EpochObservation` are read-only observations. A file
projection, successful bootstrap receipt, selected role, or decoded epoch row
must not substitute for either missing supplier. S3's startup
`CurrentPreparedFilePhase` is included: it retains the same file descriptors and
actual Controller stage through a bounded operation, and an abandoned or
refused phase permanently closes continuity. It is physical continuity, not
current writer authority.

The stack also includes `InitialStoreMetadata`, which admits instance and
artifact/schema inputs without opening or creating the serving database.
Initial image preparation and App file observation use it instead of a
previously opened `Runtime`. This closes a preparation-ordering gap, but does
not construct the missing authenticated holder or writer owner.

## Producer and continuation boundary

The final implementation belongs in `oauth/shell_oidc.rs` and the actual
management continuations, rather than returning success from the Google
timestamp comparison. For OAuthConnect and OAuthDisconnect only, it must
consume the exact Google original together with the actual enrolled role,
original lifetime, current storage/holder/writer authority, and purpose-bound
continuation. Returned DATA must not become a transferable permission.

S2's `with_current_original` lends a current `RoleStage` and `OriginalPhase` on
their owning executor. `RoleStage::with_native` lends the actual S1
`EnrolledRoleStage`; its simulation branch cannot supply a native stage. The
eventual S3 consumer must retain those borrows through the actual operation,
including known SQL commit, session creation, signing, provider dispatch and
socket writes as applicable. Each later phase needs its own current authority
check. A dropped response, unknown commit or unknown send must retain the
appropriate unresolved ownership; it must not restart either original or
create a second permit journal.

`with_consumer` now retains the same original and role through the real consumer
operation and its result. Pure input or signature refusals are known exclusions
and do not burn another human's valid original. The boundary arms immediately
before a commit, signature, session insertion or provider/socket send; errors
and unwinding after that point pessimistically retain uncertainty. The
original remains in its owning registry, permanently refused after ambiguity;
there is no timer-based regrant or restoration from SQL. App start, dispatch,
activation and disconnect hold that borrow through the actual SQLite COMMIT
and a subsequent current check. A commit error cannot be swallowed to rearm
the original. Shell session insertion, selected key loading/signing and App
signature verification use the same boundary. Provider token and account
requests retain it through their actual response-body reads.

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

S3 deliberately registers no native implementation yet: the factory refuses
before the callback, SQL or provider I/O. The actual P3/current writer/serving
owner remains unimplemented, so the production proof producer stays closed.
Preparation-only files, snapshots and an epoch boolean cannot fill this gap;
the scripted simulator cannot enter the native variant or implement its sealed
trait. This is consuming code against that contract, not a native readiness claim.

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

The positive all-suppliers-current case cannot be implemented or qualified
until the two owners above supply their genuine production boundaries. It
must then be paired with missing, expired, changed-selection and wrong-holder
cases at every protected continuation. No fixture-success factory, boolean
supplier matrix or unimplemented production owner is added here to stand in
for that campaign.

## Storage continuation in progress

The App can consume its checked original file into `AppFileContinuity` while
its original stage is still valid. The same directory/file descriptors and
actual enrollment identity survive; no pathname, projection, old grant or
serialized value can recreate them. Current physical checks take a fresh
bounded stage from that same enrollment. The initial-image check remains
separate and still rejects modified bytes. Physical continuity alone grants no
first-holder, activation, provider durability or current writer authority.

The Controller's `CurrentPhysicalFilePhase` is distinct from the initial-file
phase accepted by the first-holder exchange. It retains the actual volume,
provider, mount, directory and file checks while allowing SQLite length/content
to change after legitimate writes. Entry closes the parent continuation gate;
abandonment or failure cannot reopen it. Known physical completion is still
not a P3 or current-writer result.

Current database validation checks the canonical original store, seed, marker,
schema, scope and artifact while permitting ordinary App row changes. It
validates DATA only; a caller Connection cannot construct a native owner.

Positive bootstrap/serving requires current storage authority under the accepted
mutator/delegation trust boundary and provider durability contract. The selected engineering profile is zonal
pd-balanced storage with ext4 and the trusted Controller/node/kernel/CSI/block
path. The user accepted the Google-managed Firebase Rules service agent as a
trusted writer/impersonation path, and confirmed Chander, Sebastian and
internal-tools-infra as governance roots. That decision requests no IAM changes;
the earlier v2 IAM proposal remains unapplied. The storage-access, impersonation
and durability decisions are settled. Their actual writer/serving implementation
and native qualification remain G1's work. Enrollment, local fsync, previous
readback and an authenticated first holder cannot substitute for current
authority. Native production factories remain closed until implemented.

For a selected native bootstrap, the launcher checks only desired deployment
metadata and S3's fixed `/state` mount. It never reads an ordinary SQLite
authority row or creates the ordinary replica lock. On the final enrolled App
thread, the real Controller offer is authenticated before opening or parsing
the original file. The completed exchange is consumed into the same executor's
`AppInitialStorageContinuity`; an attempt closes before stage acquisition or
channel I/O, and cannot be retried from SQL or metadata after failure. Scoped
bootstrap participation lends that actual owner and a fresh stage from the
same enrollment, retaining refusal on error or panic. Runtime activation stays
closed pending G1's active-owner constructor. Shell receives no App file or
storage authority through this path.

Current App/Controller peer phases require distinct issuer-signed role grants
from the initial exchange and the last completed phase. A new wrapper, nonce
or acquisition domain around the same signed grant cannot refresh authority.
This exchange does not supply Shell serving permission; that requires its own
genuine narrow producer without granting Shell storage reader/writer access.

`Runtime::load` now refuses an explicitly selected native bootstrap profile
before inspecting or creating `.state` or opening SQLite. Existing SQL authority
rows cannot recreate the missing current native holder. This closes ordinary
startup for that selection while the real consuming Runtime admission factory
is absent. It does not claim that ordinary apps or explicit synthetic
verification installations have native storage authority.
