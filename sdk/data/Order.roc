import Model

# Generated typed field handles are validated against the admitted schema.
Order(a) :: { model : Str, field : Str, descending : Bool, witness : List(a) }.{
	define : Model(a), Str, Bool -> Order(a)
	define = |model, field, descending| { model: model.name(), field, descending, witness: [] }

	parts : Order(a) -> { model : Str, field : Str, descending : Bool }
	parts = |order| { model: order.model, field: order.field, descending: order.descending }
}
