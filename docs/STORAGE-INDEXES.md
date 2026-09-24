# Tables and keys

Every nominal record declared in `Models.roc` is a table. There is no storage
object to write: the platform generates the schema from the models module and the
committed [identity ledger](IDS.md), which names each model's table. A model with
business keys declares them on itself:

```roc
import pf.Table

Models :: [].{
	Link := { name : Str, owner : Str, is_deleted : Bool }.{
		table : Table(Link, _)
		table = Table.keyed(
			|row| {
				by_name: Table.unique({ name: row.name }),
				by_deleted: Table.non_unique({ is_deleted: row.is_deleted }),
			},
		)
	}

	SavedView := { owner : Str, table_key : Str, name : Str }.{
		table : Table(SavedView, _)
		table = Table.keyed(
			|row| {
				by_owner_table_name: Table.unique({ owner: row.owner, table_key: row.table_key, name: row.name }),
			},
		)
	}
}
```

A model without keys writes nothing. `table` is a type witness, not data: the
platform reads the row model and every key from its type. Because the selector
receives the model's own row, a key naming a column the model lacks does not
compile. Write each key column as `column: row.column`. Admission rejects a label
that reads a different column, including one of the same type, and a column whose
kind differs from the model's. A one-column key is `{ name: row.name }`; in Roc
`{ name }` is a block evaluating to `name`, and `Table.unique` accepts only
records. The `table : Table(Link, _)` annotation is required so these errors point
at the model rather than at generated code; `_` leaves the key types to inference.

A key contains one to eight distinct persistent fields, and an app may declare
up to 128 keys. Compound fields have canonical alphabetical order. They describe
equality tuples; field order in the Roc record does not declare result ordering.
Metadata columns such as `id` are not business key fields. Reference fields still
produce their existing foreign keys and lookup indexes automatically.

SQLite enforces a `Table.unique` tuple on every insert and update. Platform
deletion does not release a name: generated indexes never mention `deleted_at`, so
a deleted row keeps its unique value and can always be restored into it. An
application's own soft-delete flag behaves the same way — it releases nothing
unless the flag is part of the declared key. See [DELETION.md](DELETION.md).
Equality uses stored values and binary text comparison; a domain that wants
case-insensitive names must normalize them before storage. Nullable text follows
SQLite semantics: rows with a `NULL` component do not conflict with one another.
Non-unique keys append the row ID as a stable tie breaker; unique keys do not,
because that would defeat business uniqueness.

## Models and the ledger

All models live in the one `Models` module, so models may reference each other
freely; Roc rejects import cycles between modules. Each nominal record declared
directly in `Models` must have an active ledger entry, and each active entry must
name a declared model. Builds refuse a mismatch with the command that resolves it:
`xtask register-model APP TABLE Models.Type` for a new model, `xtask retire-model`
for a removed one and `xtask rename-model` for a rename. A renamed type therefore
never silently becomes a new table.

## Text domains

A model or input field typed `Text(Title)` uses the `Title` type's
`rules : TextSpec(Title)`. The platform registers every text domain the application
uses; the generated `Domains.title` constructor takes its name from the type. A
`Text(...)` type without rules is a build error.

## Migrations and planning

The migration protocol supports adding keys. It creates each index in the same
transaction as column additions and schema metadata. Existing duplicate tuples
make a unique-key addition fail, leaving the previous schema, rows and migration
journal intact. Key removal or redefinition requires a future explicit migration
operation. An ID conversion rebuilds all declared indexes and rolls back completely
if their constraints fail.

Declaring a key does not guarantee that SQLite uses it for every predicate.
For example, a leading-wildcard text search may scan matching storage. Query
selection limits bound returned rows, not rows examined by the query planner.
