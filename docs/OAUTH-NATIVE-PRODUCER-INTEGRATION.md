# OAuth native producer integration

This branch composes PRs 214 (enrollment), 211 (original owners and HTTP
executors), and 209 (native storage preparation and file continuity). It does
not enable the production fresh-human producer. The prerequisite suppliers
below are still missing from those PRs, as confirmed by their owners.

## Required suppliers

- Credential owns the closed authenticated initial-holder peer exchange. It
  must join the actual enrolled Controller and App messages within their
  original stages, before the App parses SQLite. S1's `SameEnrolledOwner` is
  enrollment continuity, not that exchange or a first-holder grant.
- G1 owns provider P3 and exclusive-mutator qualification, counter activation,
  current serving/writer authority, and final consumer settlement. The current
  `NativeStorageCreationAuthority`, `PreparedInitialFile`, and
  `PreparedFileContinuity` retain real resources, but cannot authorize serving
  mutations. `CurrentBootstrapExecution` has no production constructor.

`AuthenticatedReads` and `EpochObservation` are read-only observations. A file
projection, successful bootstrap receipt, selected role, or decoded epoch row
must not substitute for either missing supplier. The separate startup
`CurrentPreparedFilePhase` work is also physical continuity, not current writer
authority; it is not included in this dependency stack.

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
