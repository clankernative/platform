# Use generated Inputs handles. The define factory is restricted to generated code.
Input(a) :: { name : Str, decoder : Str -> Try(a, Str), encoder : a -> Str }.{
	define : Str, (Str -> Try(a, Str)), (a -> Str) -> Input(a)
	define = |name, decoder, encoder| { name, decoder, encoder }

	name : Input(a) -> Str
	name = |input| input.name

	decode : Input(a), Str -> Try(a, Str)
	decode = |input, raw| (input.decoder)(raw)

	encode : Input(a), a -> Str
	encode = |input, value| (input.encoder)(value)
}
