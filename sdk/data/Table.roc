# The storage declaration a model attaches to itself. Every model is a table;
# only a model with business keys writes one:
#
#     AdDay := { metrics : Ref(AdMetrics), date : Str }.{
#         table : Table(AdDay, _)
#         table = Table.keyed(
#             |row| {
#                 by_date: Table.unique({ metrics: row.metrics, date: row.date }),
#             },
#         )
#     }
#
# Nothing here is a runtime value. Reflection reads the row model and the keys
# from this type, so the selector is typed by the model itself: a key naming a
# column the model lacks does not compile. The annotation pins the row, which
# keeps that error on the model rather than in generated code.
Table(row, keys) :: { row_witness : List(row), key_witness : List(keys) }.{
	# A table with no business keys. The platform supplies this for any model that
	# declares no `table`, so applications never need to write it.
	plain : Table(row, {})
	plain = { row_witness: [], key_witness: [] }

	keyed : (row -> keys) -> Table(row, keys)
	keyed = |_select| { row_witness: [], key_witness: [] }

	# Keys select a record of the model's own columns. Closed tags keep the kind
	# and the columns in the type, where reflection reads them. In Roc `{ date }`
	# is a block evaluating to `date`, so a one-column key is written
	# `{ date: row.date }`; the record-only parameter rejects the block form. A key
	# label must name the column it reads, which admission also checks.

	# SQLite enforces the tuple on every insert and update. Platform deletion does
	# not release it, and nullable text components follow SQLite semantics.
	unique : { ..fields } -> [Unique(List({ ..fields }))]
	unique = |_selected| Unique([])

	# An equality tuple the host admits for selection and ordering. It enforces
	# nothing about the data.
	non_unique : { ..fields } -> [NonUnique(List({ ..fields }))]
	non_unique = |_selected| NonUnique([])
}
