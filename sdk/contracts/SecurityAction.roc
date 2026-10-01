import Input
import ProductReturnRef

# Generated descriptors carry an exact command input codec. Navigation grants
# no authority; the host admits only interactive commands at the security edge.
SecurityAction(input) :: { operation : Str, codec : Input(input) }.{
	define : Str, Input(input) -> SecurityAction(input)
	define = |operation, codec| { operation, codec }

	bind : SecurityAction(input), input, ProductReturnRef -> { operation : Str, payload : Str, product_return : Str }
	bind = |action, input, product_return| {
		operation: action.operation,
		payload: action.codec.encode(input),
		product_return: product_return.name(),
	}
}
