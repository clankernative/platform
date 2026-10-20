# Native initial storage and epoch ownership

The counter and control-slot protocol share the selected Firestore Native
database. The epoch controller is its sole protocol mutator. AppHost uses the
separately selected reader identity; SecurityShell does not acquire a counter
writer. Selecting an account or checking a decoded reply does not establish
exclusive IAM, P3 or current writer authority.

## T6 decision

Use the existing Calendar Firestore database and controller GSA from the
instance's applied authority selection. Preserve the physical database UID,
project number and immutable service-account UID. Do not create another database,
governor or permit journal. The existing permanent Create and Complete control
slots remain the only dispatch barriers. A lost send stays unresolved; elapsed
time, a matching stored request or process restart cannot recreate its permit.

Use the existing GKE Persistent Disk mounted at `/state`. Bind its PVC UID, PV
UID, CSI driver and volume handle to the immutable Compute disk ID. The current
provider readback is selection input, not an observation of the calling
process's mount. Actual admission must also join that disk to the retained
directory and current process mount under the original native acquisition.

The selected controller profile is a trusted privileged native executor on the
dedicated enrollment pool, with host PID visibility and a read-only host
`/dev/disk/by-id` directory. Its fixed adapter opens only the selected block
device read-only and compares its actual device number with the retained mount;
the provider attachment and immutable disk ID must also match. This explicitly
adds the controller and node runtime to the TCB. It grants no device, containerd
or ptrace access to AppHost or SecurityShell and makes no hostile-code
containment claim. Deployment of this profile requires the instance's normal
review/apply; it has not been applied by this change.

The controller uses the same selected filesystem UID as the AppHost for the
private initial-file directory and mode-0600 file. Provider and filesystem
identity checks still apply; a configured UID alone is not enrollment or P3.

The controller exclusively creates its private `/state/day2-native` directory
and `day2-initial.sqlite` beneath that anchor. An existing directory or file is
a refusal, including after a controller crash; startup cannot adopt it.
The original creator retains the file and directory, admitted image, private
selection and original acquisition. File sync, directory sync, complete readback
and seed/schema admission are necessary local steps. They become a provider P3
acknowledgement only in the qualified provider/runtime composition; local sync
or a receipt alone does not supply that composition.

The first holder is the actual enrolled AppHost process and its retained
ephemeral key. Bind it through the fixed native storage exchange, using actual
per-message process handles and current role/key possession. A holder row,
public key, Pod UID or signed certificate cannot reconstruct the native owner.
The controller remains distinct from AppHost, and an AppHost cannot create the
file or acquire the controller's mutation identity.

The fixed exchange endpoint is `/run/day2-native-enrollment/storage/peer.sock`. Its only initial
operations are BeginInitialHolder and ConfirmPreparedMount. The statements bind
the exact original seed, marker, file identity and image. The controller retains
its own original interval and CreatorFD; an App observation retains its own
descriptor and original role interval. Linux mount IDs are namespace-local;
their numeric equality across controller and App namespaces is not a volume
join. No arbitrary signing, pathname, descriptor adoption or generic callback
belongs in this interface.

## Retained boundaries

`PreparedInitialFile` packages the original creator, admitted layout and the
same original acquisition. `check_original` checks unchanged initial bytes and
identity. Failure remains latched even after restoration. A replacement interval
cannot renew the creator. Its serialized `PreparedFileProjection` is DATA only;
there is no inverse projection-to-owner constructor.

The App reads the controller's exact initial bytes through its own existing
read-only descriptor. It matches the creator projection's digest and validates
the complete bounded read-only SQLite image, selected schema, canonical store,
seed and marker. It does not independently initialize another database: fresh
runtime initialization generates a new random authority lineage. The distinct
`ObservedInitialImage` is readback DATA and cannot enter the original creation
layout. Authenticating that projection through the real enrolled controller
peer is still mandatory before holder participation or activation; this decoder
supplies neither permission.

Only a successfully checked preparation may consume the original creator into
`PreparedFileContinuity`. That transition captures the real `SameEnrolledOwner`
while the original preparation still passes, then moves the same file, directory
and block-device descriptors without reopening them. Failure retains the
original owner in a refused outcome. Filesystem fixtures cannot take this
transition. The original preparation stage and its spent clock are dropped;
a later current operation must supply a fresh bounded stage from the same
still-live enrolled owner and reobserve the actual selected provider attachment.
This is physical continuity, not a renewed preparation, first-holder or writer
grant. All initial-image changes still refuse; serving after legitimate SQLite
writes requires its own qualified activation transition.

The initial controller qualification budget is a 250m CPU / 256Mi memory request
and a 1 CPU / 512Mi memory limit, in one process that also owns the fixed storage
peer. There is no additional storage sidecar. These are unmeasured starting
limits; peak admitted-runtime initialization and headroom must be measured before
qualifying the deployment.

An authorized counter dispatch retains the known claim through the fixed
request, response parser and final current check. The prepared dispatch is
consumed at send, and the response still owns its execution context. It cannot
be used for a second send or an arbitrary URL/body. A malformed, lost or expired
reply cannot reconstruct send authority or clear the permanent slot.

## Remaining production composition

The native creation factory consumes the actual enrolled controller stage and
performs authenticated provider reads and native block-device/mount checks. It
has not been qualified on the live GKE profile. Complete exclusive
mutator/impersonation governance qualification, then bind the first-holder peer,
current serving transition and production bootstrap-execution factory. Recheck these
owners through known local admission commits, provider/body sends and final
settlement. Keep unknown outcomes retained. Do not treat a completed response
object as a completed human or provider exposure.

The normal app database open and initialization must consume that qualified
prepared/active storage path; an ordinary runtime must not silently adopt or
create a replacement file. Initial role enrollment precedes epoch creation.
Current serving authority must not require unchanged initial image bytes after
legitimate application writes, and an earlier successful bootstrap receipt is
not current serving authority.

Until that composition and its native qualification exist, the production
fresh-human refusal remains in place. No fixture, desired configuration, IAM
audit report, local readback or prior verification receipt may replace it.
