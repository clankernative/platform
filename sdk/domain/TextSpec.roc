# Declarative standard rules. Only generated Domains constructs Text values.
TextSpec(domain) :: { maximum_bytes : U64, nonblank : Bool, description : Str, witness : List(domain) }.{
	define : { maximum_bytes : U64, nonblank : Bool, description : Str } -> TextSpec(domain)
	define =
		|
			rules,
		| { maximum_bytes: rules.maximum_bytes, nonblank: rules.nonblank, description: rules.description, witness: [] }

	metadata : TextSpec(domain) -> { maximum_bytes : U64, nonblank : Bool, description : Str }
	metadata = |rules| { maximum_bytes: rules.maximum_bytes, nonblank: rules.nonblank, description: rules.description }
}
