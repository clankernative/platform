import Observe
import Resource

# The host builds a SELECT from the activated view/column contract. A parameter
# can only narrow that view through its declared equality filter.
Snowflake :: [].{
	Parameter :: { name : Str, kind : Str, value : Str }

	Cell : { is_null : Bool, value : Str }

	Rows : { columns : List(Str), rows : List(List(Cell)) }

	text : Str, Str -> Parameter
	text = |name, value| { name, kind: "text", value }

	integer : Str, I64 -> Parameter
	integer = |name, value| { name, kind: "integer", value: value.to_str() }

	boolean : Str, Bool -> Parameter
	boolean = |name, value| {
		name,
		kind: "boolean",
		value: if value {
			"true"
		} else {
			"false"
		},

	}

	read : Resource, List(Parameter) -> Observe(Rows)
	read = |resource, parameters| Observe.capability(
		"snowflake.read.v1",
		Json.to_str({
			handle: Resource.token(resource),
			parameters: parameters.map(
				|parameter| {
					name: parameter.name,
					kind: parameter.kind,
					value: parameter.value,
				},
			),
		}),
	).and_then(
		|raw| {
			parsed : Try(Rows, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_snowflake_result"))
		},
	)
}
