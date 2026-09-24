# Storage indexes and unique keys

Declare business keys alongside the nominal storage schema:

```roc
import pf.Index

definition = {
    schema,
    identities: "model-identities.json",
    domains: { title: Title.rules },
    indexes: {
        links: {
            by_name: Index.unique({ name: Index.field }),
            by_deleted: Index.non_unique({ is_deleted: Index.field }),
        },
        views: {
            by_owner_table_name: Index.unique({ owner: Index.field, table_key: Index.field, name: Index.field }),
        },
    },
}
```

The constructors close the `Unique` and `NonUnique` tag types for native
reflection. `Index.field` is a nominal type witness with a nonzero native layout;
the pinned compiler can otherwise alias labels in records of zero-sized fields.
The compiler reflects the table, index and field labels, the tag, and these
witnesses. Admission resolves every field
against its registered nominal model and rejects unknown fields, duplicate keys,
unsupported markers and generated SQL name collisions. There is no second schema
file. Omit `indexes` when no business indexes are needed; existing storage
definitions and serialized schemas retain their shape.

A key contains one to eight distinct persistent fields, and an app may declare
up to 128 keys. Compound fields have canonical alphabetical order. They describe
equality tuples; field order in the Roc record does not declare result ordering.
Metadata columns such as `id` are not business key fields. Reference fields still
produce their existing foreign keys and lookup indexes automatically.

SQLite enforces a `Unique` tuple on every insert and update. Platform deletion
does not release a name: generated indexes never mention `deleted_at`, so a
deleted row keeps its unique value and can always be restored into it. An
application's own soft-delete flag behaves the same way — it releases nothing
unless the flag is part of the declared key. See [DELETION.md](DELETION.md).
Equality uses stored values and binary text comparison; a domain that wants
case-insensitive names must normalize them before storage. Nullable text follows
SQLite semantics: rows with a `NULL` component do not conflict with one another.
Non-unique indexes append the row ID as a stable tie breaker; unique indexes do
not, because that would defeat business uniqueness.

The migration protocol supports adding keys. It creates each index in the same
transaction as column additions and schema metadata. Existing duplicate tuples
make a unique-index addition fail, leaving the previous schema, rows and migration
journal intact. Index removal or redefinition requires a future explicit migration
operation. An ID conversion rebuilds all declared indexes and rolls back completely
if their constraints fail.

Declaring an index does not guarantee that SQLite uses it for every predicate.
For example, a leading-wildcard text search may scan matching storage. Query
selection limits bound returned rows, not rows examined by the query planner.
