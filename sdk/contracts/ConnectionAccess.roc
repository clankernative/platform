# Private shared shape for reviewed semantic access declarations. App imports
# come from capability modules; provider scopes never appear here.
ConnectionAccess :: { value : { capability : Str, actions : List(Str) } }.{
	define : Str, List(Str) -> ConnectionAccess
	define = |capability, actions| { value: { capability, actions } }

	metadata : ConnectionAccess -> { capability : Str, actions : List(Str) }
	metadata = |access| access.value
}
