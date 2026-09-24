# Predicates, single-row lookup and ordered pages

Commands and queries use the same typed selection plans. `Query.find` and
`Tx.find` return `Some(row)` or `None`; more than one visible match fails with
`ambiguous_selection`. They do not silently choose the first row and do not
establish uniqueness. Declare uniqueness in
[Storage.definition.indexes](STORAGE-INDEXES.md); storage enforces it for every
insert and update, including writes that did not first perform a lookup.

Generated `Data` functions retain each model and field's type. For a `links`
model with indexed `name : Str` and `is_deleted : Bool` fields:

```roc
import pf.Query
import pf.Selection
import pf.Predicate
import Data

lookup = |name| Query.find(
    Selection.filter(Data.links, Data.links_name_equal(name)),
)

active_lookup = |name| Query.find(
    Selection.filter(Data.links, Predicate.all([
        Data.links_name_equal(name),
        Data.links_is_deleted_equal(Bool.False),
    ])),
)
```

The `is_deleted` field above is an application's own column, kept here because
the golinks app has one. New apps should not write one: deletion is a platform
state, reads exclude deleted rows by default, and `Selection.only_deleted`
builds the trash view. See [DELETION.md](DELETION.md).

`Selection.filter` expresses the SQL WHERE clause; `where` is a reserved Roc
keyword. A predicate checks one typed field, `Predicate.all` joins predicates
with AND, and `Predicate.any` joins them with OR. Empty AND is true; empty OR is
false. Text fields also have generated `_like` functions. LIKE follows SQLite's
pattern semantics: `%` and `_` are wildcards, and case folding is SQLite's
default ASCII behavior. Values are bound parameters, never interpolated SQL.

A compound key is expressed with ordinary predicates:

```roc
Query.find(Selection.filter(Data.saved_views, Predicate.all([
    Data.saved_views_user_id_equal(user_id),
    Data.saved_views_table_key_equal(table_key),
    Data.saved_views_name_equal(name),
])))
```

With a unique constraint on those three columns and no `NULL` components, at
most one row can match. Nullable keys retain SQLite's `NULL`-distinct semantics:
several rows can share a tuple containing `NULL`, so a lookup using `_equal(None)`
can still fail with `ambiguous_selection`.
Selecting only user and table can match many rows and normally belongs in
`Query.page`. `find` rejects a nonempty pagination cursor and always checks up
to two matching rows, regardless of the selection's page size.

## Paging

Generated `_asc` and `_desc` handles select business ordering. Every model also
has handles for `id`, `version` and `created_at`. The host appends ascending ID
as a tie-breaker unless the app explicitly includes an ID order.

```roc
Query.page(
    Selection.filter(Data.links, Data.links_is_deleted_equal(Bool.False))
        .order([Data.links_visit_count_desc, Data.links_version_desc, Data.links_id_asc])
        .paginate(input.after, input.limit),
)
```

The host applies filtering and owner scope before row limits. New selections
return opaque `sel1_` continuation handles bound to the model, predicate, order,
actor and operation. Each handle contains 256 random bits; ordering values stay
in protected host metadata and are never encoded in the public cursor. Capturing
the last row's ordering values preserves continuation after that row is deleted.
The handle does not freeze the dataset: updates to other rows' ordering values
can change subsequent pages.

Handles expire 24 hours after their latest page issuance, measured using the host-stamped invocation
time. Expired or unknown handles fail explicitly; restart at `Cursor.start`.
Each application database holds at most 10,000 active handles, with at most 8 KiB
of boundary metadata each. Creating a new handle removes expired entries, then
fails explicitly if capacity remains exhausted; it does not evict active handles.
An unchanged selection and boundary reuse the same handle, preserving preparation
revalidation. Typed cursor inputs are pinned when an invocation is accepted;
cursor inputs and results are also pinned when pages are read. Pending invocations
retain their handles across expiry and garbage collection, so delayed preparation
can resume using its original invocation time. Fresh invocations still reject
expired handles. Pins are released after invocation completion during the next
cleanup. There are at most 100,000 pins; exhausting that budget fails explicitly.
Pending pins can retain handles indefinitely within those fixed storage budgets.
Replay uses recorded observations. Page reads reserve SQLite's writer slot before
reading rows, then commit cursor metadata with the read transaction. No database
transaction remains open across a provider call, and no application mutation grant
is needed for host metadata.

Use `has_more` to determine whether to continue, and return `next_after`
unchanged. Existing ID-ordered `Data.all_links` and reference selections retain
their existing cursor behavior.

## Enforcement

Generated handles retain field types, but business fields must also belong to a
declared index or a generated reference index before the host allows their use.
Metadata fields `id`, `version` and `created_at` are always admitted.
Generated predicate/order constructors are sealed by both compiler-admission
profiles. The host independently checks model identity, field types, declared
indexes, operator shapes, predicate budgets, ordering and cursor bindings.
Selection plans are limited to 64 KiB, 512 predicate nodes, nesting depth 16,
and eight explicit ordering fields. Exceeding a limit fails explicitly.
Predicates do not grant row authority. `find` counts only rows visible under the
current policy; a uniqueness conflict does not return an inaccessible row.

Index declarations admit fields for selection; they do not promise that every
combination of LIKE, OR and ordering can use an index efficiently. Filtering a
returned page in Roc is not a replacement for complete database selection.
