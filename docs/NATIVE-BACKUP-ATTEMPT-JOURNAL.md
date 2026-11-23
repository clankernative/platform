# Scheduled-backup attempt-file component

This is a private mechanical component. There is no runtime caller, native
requester admission, activated-root supplier, counter dispatch, source grant or
CLI. A decoded file, lock, checksum, nonce or returned commitment authorizes
nothing. The schedule must remain suspended until those genuine suppliers are
implemented and qualified.

The future fixed placement is a private sibling of application restore targets:
`/state/day2-native/.day2-backup-attempts/<domain>/attempts-v1.log`. The domain
commits only installation, environment, app and CronJob UID. Changing policy or
admission generation, epoch, key, Job, operation, destination, disk or root nonce
does not produce a fresh domain. The header separately binds the exact disk and
creator nonce. This component takes an already held directory; it neither finds
nor authenticates that placement or disk.

The file has one canonical header followed by complete canonical newline-ended
records. Each record binds its ordinal, protected scheduled slot, full Intent
commitment and previous checksum. Every byte is bounded and validated. Duplicate
slots, unknown/duplicate JSON fields, malformed/partial tails, changed birth,
reordered/repeated records and exhausted capacity refuse. Limits are 4,096
records, 1,024 bytes per line and 2 MiB for the complete file. There is no eviction,
rollover, truncation, repair or automatic new root.

Creation is exclusive and preserves an orphan after any uncertain outcome.
Reopen is existing-only. The actual file is exclusively locked without waiting,
private mode and single-link checks join its held and named identity, and its
complete bytes are compared before an append. An append first poisons its owner,
then writes, syncs the file and directory, checks identities and reads back the
entire expected image. Only successful completion clears that local poison and
returns historical commitment DATA. A complete persisted attempt remains spent
even if its acknowledgement or remote create result was lost. Partial persisted
tails refuse the whole root without changing its bytes.

The accepting driver must impose this additional ordering with actual owners:

1. Establish known external create-only birth and durable local activation of
   the exact physical root. Serialize all native consumers of that root. Missing,
   replaced, ambiguous or orphaned activated state cannot be recreated or adopted.
2. Admit the protected genuine scheduled requester under the same Controller,
   source, epoch, artifact, transport and original. Check the same held physical
   root before and after the append; the file lock alone is not authorization.
3. Complete append durability and native postchecks before acknowledging locally
   and before counter May. Only a known successful create-only remote reservation
   can proceed to private source reads. Unknown remains spent across process death
   and remote absence. No automatic Job/backoff/native retry is supplied.

An absent slot is preparation DATA only on the same already activated root under
qualified completeness, durability and nonrollback assumptions. There is no
proof of no earlier send from missing bytes or a lost in-memory acknowledgement.
The checksum chain detects corruption, not a trusted administrator's same-inode
rollback or selective erasure. A regression deliberately demonstrates that
limitation. Accepting recovery requires actual physical durability, exclusive
writer/cleanup governance and retained external bindings; if those premises
cannot be established, it must refuse or use a genuine monotonic anchor.

Application restore creates a new `restore-<operation>` child and must never
copy, reset or delete this sibling. Backup/archive cleanup must not touch it.
Do not recycle its disk or the external root/attempt records while that scheduling
delegation or any upload consumer can still issue effects. Retiring a delegation
and creating a reviewed new CronJob UID is a separate governed change, not retry.

Portable tests exercise actual local files and locks, partial writes, retained
versus named substitution, permissions/links, complete-image bounds, independent
generated histories and twice replay with private source-bound failure bundles.
These do not establish power-loss durability, native original/physical admission,
cross-container locks, protected Kubernetes CREATE provenance or live provider
completion. Those remain separate Linux/native F qualification obligations.


## External root-binding codec (non-operational)

The separate fixed control-store namespace is
`day2_scheduled_backup_roots_v1/<scope-and-CronJob-key>`. A root record binds the
exact canonical header, physical disk and public creator nonce, plus the
immutable control database UID. The create uses exactly one write with
`currentDocument.exists=false`. The shared strict single-write acknowledgement
parser returns comparison time DATA only; it is not native completion or local
activation. Root and attempt records have different fixed namespaces and purposes.

Existing records must have exact name/fields, canonical payload, expected full
binding/digest and equal creation/update times. Key rotation does not choose a
fresh address. A changed disk/creator/header/database incarnation cannot be
adopted from an existing row. A missing or matching row cannot resume a local
unknown turn. No reset, delete, update, retry, activation or positive reboot
constructor is supplied.

A later sealed creator must use the actual fully admitted physical continuity,
current Controller/lineage/conditional writer and the same ordinary five-second
original. The warm full-durability refusal remains intact; no bootstrap clock is
substituted. Pending metadata written before final posts is not positive
settlement. If a later release proof is added, its secret must be distinct from
public creator nonces and released only by consuming Known after every creator
post; it proves neither the receiver's later persistence nor a fresh role/source.
Positive recovery remains closed pending that complete proof and qualified
nonrollback history. This codec has no runtime/native accepting caller.

## Native creator (not installed)

The fixed creator borrows the actual active Controller's physical, retained
counter and lineage owners on the same ordinary five-second Current original.
The checked enrollment policy selects only the configured Scope/CronJob. The
current volume must already be Admitted; full bootstrap admission and the warm
full-durability refusal are unchanged. No second provider acquisition, admin
read relabeling or new role is used for pending metadata.

The whole parent stays live through the fixed private directory/header creation,
file and directory sync/readback, immutable external create, a strong post-read
of the actual lineage, counter completion and consuming physical completion.
Only infallible continuity moves follow the final post. An ephemeral private
whole-parent seal binds the lower write to its exact actual counter, stage and
pending resources. The ordinary counter read port still refuses writes.

This first create is bracketing, not an atomic assertion of current writer at
provider commit. A concurrent lineage change may leave an obsolete pending or
orphan row; it cannot produce Known or ever be adopted. Known is continuity of
this actual completed creator, not source/capture authority or a statement that
the writer was current at the instant of commit. Positive reboot/recovery stays
closed, and no row/file/marker supplies a constructor. Runtime installation,
protected CREATE provenance, native execution and five-second fitness remain
unqualified. No scheduling or deployment is enabled.

## Retained attempt image (mechanical continuation)

The held root keeps the exact previously verified canonical image. A bounded
canonical Intent can advance it only through the existing real append, file
sync, directory sync, complete readback and held/named identity checks. A new
`AttemptFile::hold` uses that expected image and the same locked open description;
it never adopts current disk bytes as its expectation. The image moves only
after the actual append returns known. A separate sticky refusal bit is set
before fallible work, survives every temporary hold and is also set by the
actual native parent's refusal. No later valid image or absent remote row can
clear it. Recreating an existing named root still refuses.

These are filesystem mechanics and historical DATA, not an authenticated
scheduled request, native counter May, source loan or completion. The accepting
request factory remains closed while protected persisted-CREATE provenance is
unavailable. Any later actual adapter must retain the same whole parent through
local durability, reservation, source, transfer and final consuming posts.

Portable histories join actual retained-file appends to the actual create-only
reservation codec, with an independent numeric-slot oracle and twice replay.
They model pre-send post failure, lost/absent remote outcome, strict non200 ACK,
post-ACK failure, malformed tail and process-drop/recreation refusal. Complete
attempted failure prefixes and source-bound programs are saved as bounded
private DATA. Modeled posts and codec send-encoding transitions are not real
native/provider effects. Process drop/reopen is not a power-loss durability
qualification; genuine admission, crash cuts, nonrollback retention and five-
second fitness remain obligations for the approved F execution.
