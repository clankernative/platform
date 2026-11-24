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
