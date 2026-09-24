Field(a) :: { name : Str, witness : List(a) }.{
	define : Str -> Field(a)
	define = |name| { name, witness: [] }

	name : Field(a) -> Str
	name = |field| field.name
}
