# Use generated Outputs handles; the host independently checks output shape and budgets.
# The define factory is restricted to generated code, not app-authored encoders.
Output(a) :: { key : Str, encoder : a -> Str }.{
	define : Str, (a -> Str) -> Output(a)
	define = |key, encoder| { key, encoder }

	name : Output(a) -> Str
	name = |output| output.key

	encode : Output(a), a -> Str
	encode = |output, data| (output.encoder)(data)
}
