# Native backup mechanical components

`security_epoch/native_backup.rs` contains private snapshot and image-verification
components. It has no production requester, native authorization constructor,
owner enrollment, destination selection, CLI/HTTP backup route or live factory.
The separate requester/destination policy remains undecided. Ordinary backup's
native refusal and native scheduled-backup suspension remain unchanged.

The memory copier exclusively borrows the actual read-only SQLite transaction,
pins its main snapshot, bounds the logical image to the existing native restore
profile, and executes at most sixteen pages per explicit step. The exclusive
borrow prevents a caller from rolling back and beginning another transaction
while the copy handle is in use. Busy/Locked, progress changes, abandonment and
misuse refuse the target permanently; there is no sleep/retry or source journal
mutation. No Connection or native authority getter is exposed.

The copy result is an opaque owned memory database, checked for size, integrity
and reserved schema objects. It is logical historical DATA, with no connection
or callback getter. Consuming it for image serialization additionally requires
the unchanged standalone SQLite header. A rollback-journal source can produce
that image; the pinned SQLite library preserves a WAL source's 2/2 format bytes
and serialization **refuses** it. No header patch, VACUUM, source journal mutation
or scratch-file fallback is used. Restorable WAL export is an open mechanical
gap; these components do not finish the native backup producer or qualify F05/F34.

Standalone images must match the same canonical manifest/artifact verifier used
by restore. The unchanged native
archive graph predicate is shared with existing capture. Image consistency
neither establishes native source provenance nor verifies an entire published
archive's files/modes/durability.

The future native driver must retain its genuine original, parent, physical
cohort, counter and App exclusion around every actual step, close the source
transaction before artifact/filesystem/provider work, then retain the actual
source Connection through publication and close/postcheck it before release.
The component's memory Connection close is not that source close. No component
result supplies approval, a current epoch, backup permission or a writer.

Tests use real SQLite, explicit controlled source transactions and an independent
committed/pending model. Generated histories replay twice; divergent or refused
execution retains the bounded schedule, source identity and closed per-step
observations under `artifacts/control-slot-replays/native-backup-component-*`.
The existing CI retention path selects their private `replay.json.gz` files;
compression preserves the complete bounded JSON, and replay refuses truncation,
trailing bytes or excessive decompression.
Rows, native owners, environment and underlying error text are not retained.
A deliberate wrong oracle, actual abandoned-copy/unwind cuts and missing
observation cases exercise refusal retention and replay. These are component tests, not
genuine Controller/Shell or Linux/native qualification.

`xtask build-restore-native` normally builds the dedicated F overlay. Full verify
requires that build and the artifact-dependent canonical-verifier regression;
FAST explicitly declares its artifact-dependent exclusion. The latter test uses
normally built F and Reports artifacts with a controlled metadata initializer,
not a manufactured enrolled owner. See the fixture README for configuration and
native qualification gaps.
