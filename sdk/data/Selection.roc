import Model
import Cursor
import PageSize
import Predicate
import Order

# Generated Data functions retain model and field types. The host requires
# indexed fields and validates the plan; this is not an authority token.
# Pagination bounds returned rows, not the number of rows scanned by SQLite.
Selection(a) :: {
	model : Model(a),
	predicate : Predicate(a),
	orders : List(Order(a)),
	field : Str,
	value : Str,
	after : Cursor,
	limit : PageSize,
	legacy : Bool,
	deleted : Str,
}.{
	indexed : Model(a), Str, Str, Cursor, PageSize -> Selection(a)
	indexed = |model, field, value, after, limit| {
		model,
		predicate: Predicate.define(model, field, "equal", Json.to_str(value)),
		orders: [],
		field,
		value,
		after,
		limit,
		legacy: Bool.True,
		# Live rows only unless a caller asks otherwise.
		deleted: "exclude",
	}

	all : Model(a), Cursor, PageSize -> Selection(a)
	all = |model, after, limit| {
		model,
		predicate: Predicate.all([]),
		orders: [],
		field: "",
		value: "",
		after,
		limit,
		legacy: Bool.True,
		# Live rows only unless a caller asks otherwise.
		deleted: "exclude",
	}

	filter : Model(a), Predicate(a) -> Selection(a)
	filter = |model, predicate| {
		..all(model, Cursor.start, PageSize.default),
		predicate,
		legacy: Bool.False,
	}

	# Include soft-deleted rows alongside live ones.
	#
	# Reads exclude them by default, everywhere, so a listing cannot accidentally
	# show deleted work. An audit or a reconciliation that needs the whole set
	# has to say so here — which means the mistake an application can make is a
	# missing row on a trash screen, never a deleted row surfacing as live.
	including_deleted : Selection(a) -> Selection(a)
	including_deleted = |selection| { ..selection, deleted: "include" }

	# Soft-deleted rows only: the trash view.
	#
	# Separate from `including_deleted` so a caller never has to inspect a row to
	# find out whether it is deleted — everything this returns is. That is what
	# keeps deletion state off `Model.Entity`, which every operation returning a
	# row would otherwise have to document.
	only_deleted : Selection(a) -> Selection(a)
	only_deleted = |selection| { ..selection, deleted: "only" }

	order : Selection(a), List(Order(a)) -> Selection(a)
	order = |selection, orders| { ..selection, orders, legacy: Bool.False }

	paginate : Selection(a), Cursor, PageSize -> Selection(a)
	paginate = |selection, after, limit| { ..selection, after, limit }

	model : Selection(a) -> Model(a)
	model = |selection| selection.model

	bounds : Selection(a) -> { field : Str, value : Str, after : Cursor, limit : PageSize, legacy : Bool }
	bounds = |selection| {
		field: selection.field,
		value: selection.value,
		after: selection.after,
		limit: selection.limit,
		legacy: selection.legacy,
	}

	encode : Selection(a) -> Str
	encode = |selection| Json.to_str({
		predicate: selection.predicate.encode(),
		orders: selection.orders.map(Order.parts),
		after: selection.after.to_str(),
		limit: selection.limit.to_i64(),
		deleted: selection.deleted,
	})
}
