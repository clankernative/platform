# Native backup mechanical components

`security_epoch/native_backup` implements private historical snapshot, standalone
image and canonical archive components. No production requester, enrolled owner,
native authorization constructor, destination grant, signing/CLI/HTTP route or
live supplier is installed. The scheduled requester policy is proposed, not
adopted. Ordinary native-backup refusal and schedule suspension remain in place.

The RAM copier exclusively borrows the real read-only SQLite transaction, pins
its main snapshot, and copies at most sixteen pages per explicit step. The borrow
prevents ROLLBACK/BEGIN substitution through that transaction. Size/progress,
attached-database and unsupported runtime-generation checks remain strict.
Busy/Locked, abandonment, unwind and misuse permanently refuse the target.

## Standalone WAL conversion

The owned RAM result contains logical historical DATA. Raw serialization of a
WAL copy still has2/2 format flags and is refused by the existing standalone
image guard. Every supported source uses one explicit conversion path:

1. Create an explicit0700 private directory and exclusively created0600 file.
   Retain creator descriptors; accept no caller filename or Connection.
   Compare SQLite’s actual retained Unix-VFS MAIN descriptor through the existing
   mechanical store comparison, not merely the pathname. Named creator checks
   use no-follow metadata lookup: no second database descriptor is opened/closed
   while SQLite owns POSIX locks.
2. Consume only the captured RAM content, copying at most sixteen pages per
   explicit step into that exact file. Use zero busy timeout and no retry.
3. Ask SQLite itself to leave WAL through `PRAGMA journal_mode=DELETE` on the
   private copy. Observe memory/destination close, require no sidecars, and read
   the bounded image through the retained creator descriptor.
4. Require strict1/1 flags, image size/integrity and canonical consistency.

No output byte is patched, no VACUUM or row/schema reconstruction occurs, and the
source database's journal mode stays unchanged. Creator replacement, mode loss,
in-place changes, incomplete progress and post-completion reuse refuse.

A read-only page comparison preserves every byte except SQLite's journal flags
at18/19 and bookkeeping words at24..27,40..43 and92..95. These are constrained
separately: strict1/1 output flags, equal change-counter/version-valid words, and
the actual fresh destination's known initial schema cookie0 incremented once by
SQLite backup completion. Application/user versions, SQLite library version,
rowids, private/history/debt pages and free pages remain compared. This is a
preserved-page comparison with a checked header transition, not universal
whole-file equality or native-source authentication. The canonical manifest,
artifact, historical authority and supported-graph verifier remains mandatory.
See [SQLite backup](https://www.sqlite.org/c3ref/backup_finish.html) and the
[SQLite file header](https://www.sqlite.org/fileformat.html#the_database_header).

## Canonical historical archive

The archive encoder consumes a verified image and matching manifest with an
already-admitted artifact. It uses that artifact's exact declared file catalog
and digests; it performs no ordinary worker re-admission in production. Every
copied input/output byte, complete source/output inventory, path, type, mode and
creator is checked. Symlinks, aliases, unknown members and unsupported provider,
companion or runtime-generation graphs refuse rather than being stripped.

Encoding and readback progress in bounded64KiB steps with a finite work limit,
private exclusive output files, no-follow/nonblocking reads, retained identities
and absorbing refusal. `backup.json` is the last local member. The root contains
only `app.sqlite`, `backup.json` and the selected bundled artifact. Files and
directories are synced before a positive historical result. The shared pure
native inventory/commitment format is the same one used by existing restore
capture, not a parallel archive format.

The returned path, manifest and commitment are historical DATA/custody. They
supply neither backup permission nor a native completed-handoff witness, current
epoch, writer or restore approval. A failed check stays refused after repair.
No offsite upload or COMPLETE publication is performed by these components.

## Genuine-driver obligations and qualification

The future driver must retain its genuine original, parent, physical cohort,
counter and App exclusion around constructors, every explicit copy/encoding
step and final verification. Close the actual source transaction before artifact
or filesystem work; retain and close/postcheck the real protected source
Connection before releasing its actual owner. Closing the component's historical
RAM connection is not that source close. Native signing/transfer/final posts and
consuming handoff remain separate unsupplied work. Existing five-second originals
and all resource bounds remain unchanged; no timing fitness is claimed here.

Tests use real SQLite and an independent committed/pending oracle. Generated
histories reopen standalone output images, replay twice and retain complete,
bounded gzip counterexamples via the existing CI path. Rows, owners, environment
and underlying error text are not retained. Header/content mutations, creator
and alias loss, no-retry Busy, abandonment/unwind and post-completion misuse are
negative controls. These are portable components, not genuine native owners.

The normal F/Reports fixture case executes the actual archive encoder, reopens
its produced artifact/database through the canonical verifier and exercises
irreversible output-tamper refusal twice. Full verification requires the normal
F Build and this artifact-dependent case; FAST retains its declared exclusion.
Local component success does not qualify Controller/Shell/F or a live backup.
