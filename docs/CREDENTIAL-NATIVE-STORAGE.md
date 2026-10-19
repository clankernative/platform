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

The controller exclusively creates `day2-initial.sqlite` beneath that anchor.
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

The fixed exchange endpoint is `/run/day2-native/storage.sock`. Its only initial
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

An authorized counter dispatch retains the known claim through the fixed
request, response parser and final current check. The prepared dispatch is
consumed at send, and the response still owns its execution context. It cannot
be used for a second send or an arbitrary URL/body. A malformed, lost or expired
reply cannot reconstruct send authority or clear the permanent slot.

## Remaining production composition

These boundaries do not themselves install a storage issuer, P3 owner, current
writer or production bootstrap-execution factory. Complete the actual
provider/mount join and exclusive mutator/impersonation governance qualification,
then bind the first-holder peer and current serving transition. Recheck these
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
