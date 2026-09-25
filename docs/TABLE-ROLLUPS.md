# Table rollups (spike)

A model can declare totals beside its keys. The host maintains them inside the
same SQLite transaction as each source create, update, deletion and restore.
Applications do not write the totals or schedule repair commands.

```roc
WorkflowRun := { repo : Str, created_time : I64, duration : I64 }.{
    table : Table(WorkflowRun, _)
    table = Table.keyed(|row| {
        daily: Table.rollup(
            { repo: row.repo, created_time: Table.day(row.created_time) },
            { count: Table.count, duration: Table.sum(row.duration) },
        ),
    })
}
```

`Data.workflow_runs_daily` is a read-only model handle with structural row values
`{ repo : Str, created_time : I64, count : I64, duration : I64 }`. It supports the
ordinary `Query`/`Tx` reads and `Selection` filters, ordering, find and cursor
pagination. Every group and measure has generated equality and order handles;
text also has `like`. Membership uses `Predicate.any` with equality predicates.
Filter dimensions belong in the group declaration, then reads select the desired
groups. This spike does not declare a separate predicate inside `Table.rollup`.

```roc
Selection.filter(Data.workflow_runs_daily,
    Data.workflow_runs_daily_repo_equal("platform"))
    .order([Data.workflow_runs_daily_created_time_desc])
    .paginate(Cursor.start, PageSize.maximum)
```

## Checked declaration

The vocabulary is stored integer, boolean and text group columns, with optional
`Table.hour`, `Table.day` or `Table.week` on signed integer Unix seconds. Buckets
are UTC starts; weeks start Monday, including before the epoch. Measures are
`Table.count` and `Table.sum` of an I64 column. The label of any column read must
name that column, because reflection sees types rather than lambda behavior.
Literal declarations are checked before reflection: computed values, helper
callbacks, swapped same-type fields and transformed witnesses are rejected.
Nominal text rules remain those of the source model.

Admission checks model/table/handle collisions, column types, duplicate labels,
one to eight group columns and measures per rollup, and at most 32 rollups per
schema. Writes to a rollup cannot be admitted in an app execution contract and
are independently rejected by the host. Rollup IDs have definition-specific
prefixes and deterministic, non-reused sequence payloads. They are transient
read handles, not stored foreign keys. Group IDs may change after edits or
rebuilds; cursors have the same live-data semantics as other selections and are
bound to the schema, actor, operation, predicate and order.

## Authority and limits

A rollup inherits the source model's read grant for the current operation and
actor. There is no separate grant that can bypass source authority. For an
owner-scoped actor, the owner column must be an unbucketed group dimension;
otherwise the host refuses the read with `rollup_requires_owner_group`. When it
is present, the SQL owner predicate selects only that actor's groups before
pagination. An administrator sees all groups only when the source policy allows
it. This prevents an aggregate from mixing unauthorized rows into an actor's
result. The owner-dimension requirement is enforced at runtime in this spike.

Pages remain limited to 100 rows and existing invocation step/collection budgets
still apply. Rollups reduce rows read; they do not remove the budget. A long
window over sufficiently many groups can still fail explicitly. There is no
new unbounded app scan or raw SQL interface. Each group/measure has an index,
and the group has a composite unique index; arbitrary compound selections may
still scan/filter/sort within the host's existing SQLite progress limit. This
spike does not prove an optimal compound access path or a separate scan budget.

Each source write touches its declared rollups and their indexes. Empty groups
are removed, including groups whose sum is zero when their last row leaves.
Groups with live rows and zero sum remain. Signed integer overflow aborts the
source transaction; it never publishes rounded REAL totals. Intermediate sums
must also fit I64. Soft-deleted source rows contribute nothing, so later physical
retention does not change totals. There is no automatic horizon expiration:
trailing windows select daily/hourly/weekly groups newest first and stop at the
window boundary.

## Migration and verification

Rollups participate in the storage schema digest. A reviewed migration creates,
changes or removes rollup tables and maintenance triggers transactionally.
New/changed totals rebuild from live source rows using SQL grouping; failure
(including overflow) rolls back the DDL, totals and schema publication. Unchanged
rollups are preserved. Source-model additions and arbitrary source backfills are
still outside the existing migration protocol. In particular, the CI Status
policy-bot event conversion is tested in a fresh instance, not a production
migration of an existing tally-only database.

Runtime property inspection and storage snapshot validation compare every
rollup against a SQL recount in the same snapshot. Platform tests cover random
reclassification histories, zero sums, moves between groups, soft delete,
restore, physical removal, overflow rollback, pre-epoch buckets, migration and
owner-scoped cursor reads. App-owned invariants still describe source facts.

The optional `ci_status_rollups` integration test takes
`CI_STATUS_BASELINE_ARTIFACT` and `CI_STATUS_ROLLUP_ARTIFACT`, seeds identical
synthetic CI facts, compares complete scorecard outputs, and measures warm direct
runtime invocations. It requires both apps to have been built from this platform.
This is a local spike, not production qualification.

## CI Status comparison

The re-port removes three files, reducing authored Roc from 1,814 to 1,603 lines
and command code from 765 to 570 lines. Its identical-data comparison passed
for all three scorecard windows and SQL recounts. The measured warm medians were:

| Direct runtime call | Manual tally | Rollups |
| --- | ---: | ---: |
| Scorecard: 7 / 30 / 90 days | 41.1 / 86.3 / 86.8 ms | 51.0 / 102.9 / 100.8 ms |
| Recent runs: 100 rows | 41.2 ms | 48.8 ms |
| Record run | 40.7 ms | 39.2 ms |

This spike simplifies correctness and authoring but does not improve read
latency. Four rollup selections replace one tally selection; the test does not
isolate all sources of the latency difference. Both paths remain bounded.
`MIGRATION.md` in the CI Status branch records the dataset, behavior differences,
and existing-database migration limitation.

Reproduce after building both app revisions with this platform:

```text
CI_STATUS_BASELINE_ARTIFACT=<manual-tally-artifact> \
CI_STATUS_ROLLUP_ARTIFACT=<rollup-artifact> \
cargo test --locked -p day2 --test ci_status_rollups -- --ignored --nocapture
```

The test retains its temporary instance and verification evidence, printing the
path before execution. It uses synthetic facts and direct runtime calls; it does
not reproduce the historical HTTP benchmark's exact data or transport.
