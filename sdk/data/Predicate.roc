import Model

# Generated field functions supply the model, operator and exact scalar codec.
# The host validates every node independently; these are plans, not authority.
Predicate(a) :: { expression : Str, witness : List(a) }.{
	define : Model(a), Str, Str, Str -> Predicate(a)
	define = |model, field, kind, value| {
		children : List(Str)
		children = []
		{ expression: Json.to_str({ kind, model: model.name(), field, value, children }), witness: [] }
	}

	all : List(Predicate(a)) -> Predicate(a)
	all = |predicates| {
		expression: Json.to_str({
			kind: "all",
			model: "",
			field: "",
			value: "",
			children: predicates.map(|predicate| predicate.expression),
		}),
		witness: [],
	}

	any : List(Predicate(a)) -> Predicate(a)
	any = |predicates| {
		expression: Json.to_str({
			kind: "any",
			model: "",
			field: "",
			value: "",
			children: predicates.map(|predicate| predicate.expression),
		}),
		witness: [],
	}

	encode : Predicate(a) -> Str
	encode = |predicate| predicate.expression
}
