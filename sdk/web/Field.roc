Field(a) :: { name : Str, witness : List(a) }.{
	define : Str -> Field(a)
	define = |field_name| { name: field_name, witness: [] }

	name : Field(a) -> Str
	name = |field| field.name
}
