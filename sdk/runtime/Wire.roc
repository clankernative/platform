Wire :: [].{
	Context : {
		invocation_id : Str,
		actor : Str,
		now : I64,
		authentication : Str,
		caller : List(Str),
		authenticated : Str,
		delegation_rule : Str,
	}

	Instruction : {
		kind : Str,
		model : Str,
		id : Str,
		expected_version : I64,
		data : Str,
		filter_field : Str,
		filter_value : Str,
		after : Str,
		limit : I64,
	}

	Observation : { instruction : Instruction, result : Str, error : Str }

	Request : { operation : Str, input : Str, context : Context, observations : List(Observation) }

	Response : { kind : Str, instruction : Instruction, result : Str, error : Str, consumed : U64 }

	Row : { id : Str, version : I64, created_at : I64, data : Str }

	empty : Instruction
	empty =
		{
			kind: "",
			model: "",
			id: "",
			expected_version: 0,
			data: "",
			filter_field: "",
			filter_value: "",
			after: "",
			limit: 0,
		}
}
