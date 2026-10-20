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

The selected future controller entrypoint is
`/usr/local/bin/day2-epoch-controller`, a dedicated process owning both storage
and the fixed peer. That binary and its image/code pin are not supplied yet.
AppHost and SecurityShell remain `/usr/local/bin/day2-host`; the controller must
not be admitted under that path as a substitute. An explicit read-only native
enrollment path allowlist may name the future controller, but a missing binary
or missing current identity still refuses enrollment.

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

The fixed exchange endpoint is `/run/day2-native-enrollment/storage/peer.sock`.
The closed exchange is Hello, Offer, Confirm, Complete and Accepted. Both role
statements, both fresh nonces, the original intervals and the exact seed,
marker, file identity and image are bound into the signed transcript. The
controller retains its own original interval and CreatorFD; an App observation
retains its own descriptor and original role interval. Linux mount IDs are namespace-local;
their numeric equality across controller and App namespaces is not a volume
join. No arbitrary signing, pathname, descriptor adoption or generic callback
belongs in this interface.

The Controller authenticates the unprivileged App through each actual received
SCM_PIDFD and its executable/process/namespace checks. The App retains the
Controller's actual received kernel handle and verifies the same live issuer's
signed Controller grant plus fresh key possession. This does not give the App
ptrace or containerd access or claim independent privileged-process inspection.
The original CLOEXEC seqpacket socket must remain connected around each message
and final admission. HUP, including a buffered final reply after peer closure,
refuses. The kernel handle alone would not detect an exec of a still-live peer.

The App authenticates Offer before opening or parsing the projected file.
`AppPreparedFile::observe_existing` requires that actual offer rather than raw
projection DATA. Its received Complete and own final file checks precede
Accepted; a Controller send alone is not the App receipt. The actual sender
handles, channel, file and original clocks remain owned after the exchange.
An App enrollment can attempt initial participation only once. The Controller's
file continuation was already pessimistically closed before the exchange, so
drop, error, expiry or unknown disposition cannot restart either side with a
fresh stage. These owners still grant neither P3 nor current serving authority.

Known initial completion may consume the authenticated holders into peer
continuity. The App also consumes its original checked file into
`AppFileContinuity`; the Controller finishes its known initial file phase so
its caller can retain the same `PreparedFileContinuity`. The original channel,
sender handles, transcript and enrollment identity remain retained. The actual
key stays with the original enrollment owner; losing that owner refuses every
future phase. Nothing recreates a key or descriptor from a projection.

A later peer phase performs CurrentHello, CurrentOffer, CurrentAck and
CurrentReady on that same connected socket. Both participants must supply new
issuer-signed stages. The exchange binds the initial transcript, checked
nonwrapping sequence, closed purpose, exact request digest and both fresh
nonces. Original identity/liveness checks do not renew the historical grant.
The returned current-peer phase retains the actual narrowed acquisition and
fresh signed statement. Every check and known completion borrows the same
stage again and verifies its owner, acquisition domain/origin/deadline and exact
statement. It does not hold a long mutable stage borrow that would prevent the
physical/provider owner's own postchecks.

Beginning a phase closes the local socket disposition before fallible work.
Drop, uncertainty and expiry cannot reopen it. A late completion cannot settle
a different paused sequence. Terminal refusal remains possible after known
completion without a live stage, clock or request. `finish_checked` releases
the peer scope only after all physical/provider/original/consumer postchecks;
it is distinct from recording a consumer's known result. This in-memory socket
disposition is neither another distributed permit journal nor storage authority.
Current peer identity alone still supplies no P3, active epoch or writer.

## Retained boundaries

`PreparedInitialFile` packages the original creator, admitted layout and the
same original acquisition. `check_original` checks unchanged initial bytes and
identity. Failure remains latched even after restoration. A replacement interval
cannot renew the creator. Its serialized `PreparedFileProjection` is DATA only;
there is no inverse projection-to-owner constructor.

Fresh image preparation takes `InitialStoreMetadata`, not `Runtime::load`.
The metadata loader admits the desired Instance and artifact, checks schedule
and ingress bindings, and retains the exact selected Instance digest. It has no
serving database path and does not create, open or inspect `.state`. The same
framework initializer operates only on the caller's fresh memory transaction;
a changed Instance selection or an already initialized database refuses. The
ordinary Runtime retains its existing active-database selection behavior. This
separation is schema admission only: the authenticated first-holder and current
serving factories must still supply their actual native owners before file use.

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

`begin_initial_phase` borrows that same retained file and owns a fresh actual
Controller stage. Provider checks, exact unchanged-image checks and the closed
first-holder exchange all spend this phase's original deadline, including work
already done before the exchange. This does not restart preparation. The typed
phase lends only its same stage to the fixed peer and rechecks the file before
and after peer work. App scheduling need not fit inside an already completed
preparation's interval.

Phase entry pessimistically closes the parent continuation gate. Dropping or
abandoning the phase needs no destructor to keep it refused. Error or unknown
handshake outcome cannot restore that gate or begin a replacement phase. Only
the fixed operation's known success and final current checks may call
`finish_checked`; this method alone creates no authenticated peer, first holder,
P3 or writer authority. The peer factory must still retain actual identities,
keys, channel and original handshake disposition, and authenticate the offer
before any App SQLite parsing.

The initial controller qualification budget is a 250m CPU / 256Mi memory request
and a 1 CPU / 512Mi memory limit, in one process that also owns the fixed storage
peer. There is no additional storage sidecar. These are unmeasured starting
limits; peak admitted-runtime initialization and headroom must be measured before
qualifying the deployment.

The proposed controller KSA and Deployment live in the provisioner's separate
enrollment namespace, with the selected existing controller GSA. That namespace
cannot reference the App namespace's PVC. The proposed controller `/state` mount
is the selected same-node CSI global mount with private propagation; its exact
workload path and privileged profile still require review and native admission.
Names and a host path cannot replace the provider/device/mount joins. AppHost
and SecurityShell retain their separate unprivileged workload profiles.

The optional `deploy/integrations/gke-security-epoch-access` root supplies the
missing API metadata and TokenReview prerequisites. Each GSA gets self-token
mint only, and only the controller gets selected disk/instance and PVC/PV/Node
reads. It grants no Firestore mutation or cross-account impersonation. The
instance owns the actual selections and separate state prefix. This source plan
is unapplied and is not evidence of exclusive effective IAM, qualified storage,
current serving or available controller capacity.

An authorized counter dispatch retains the known claim through the fixed
request, response parser and final current check. The prepared dispatch is
consumed at send, and the response still owns its execution context. It cannot
be used for a second send or an arbitrary URL/body. A malformed, lost or expired
reply cannot reconstruct send authority or clear the permanent slot.

## Remaining production composition

`InitialStorageContinuity::establish` now consumes the actual prepared-file
continuation and a new enrolled Controller stage. Its fixed operation performs
the authenticated initial App exchange, checks the joined disk/attachment and
live ext4 profile, synchronizes the same file and private directory, and reads
back the unchanged admitted image. Failure returns the refused original file
owner; no success flag or projection can reconstruct the owning result.

The selected durability fault model trusts Persistent Disk and the admitted
Linux/ext4/CSI/node/Controller stack. Google documents stable-media completion
for a successful Persistent Disk write command. The native checks join that
provider to the actual retained descriptors; a local sync in an unrelated
filesystem is insufficient. The live ext4 options must report ordered data and
enabled barriers, and the selected block device must have a healthy internal
journal. Unsupported/ambiguous kernel metadata refuses. Provider/kernel bugs,
administrative deletion or rollback and permanent zonal loss are outside this
conditional model; this is not a regional availability guarantee.
[Compute Engine Persistent Disk FAQ](https://docs.cloud.google.com/compute/docs/faq#persistent_disk),
[Linux ext4 documentation](https://cdn.kernel.org/doc/html/latest/admin-guide/ext4.html).

Known establishment retains the SAME file, volume, channel and authenticated
first holder. Each `CurrentStorageBootstrapPhase` owns a fresh physical phase
and new peer handshake, bound to the exact original seed and request. Completion
must select the same actual first App participant's Pod, process incarnation and
ephemeral key. The enclosing continuation closes before fallible work, and only
known completion after all final checks releases it. Errors, unknown outcomes,
drop and a failure after the peer's local completion leave the enclosing owner
closed. The new private owner types reject cloning, serialization and thread
transfer. These types supply neither effective IAM nor active epoch/writer or
Shell serving authority; no production bootstrap-dispatch factory is enabled.

The App counterpart, `AppInitialStorageContinuity`, consumes its genuine
authenticated first holder and retains the SAME read-only file and peer in one
private owner. Each `CurrentAppStorageBootstrapPhase` checks that file around
the fresh handshake and through final completion on the same actual App stage.
It cannot receive a Controller stage, mutation credential or reconstructed file
owner. The Controller rechecks its joined durability operation within each new
bootstrap stage before advertising that phase. Neither side reuses the original
grant or treats the historical durability completion as a configuration lease.

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
