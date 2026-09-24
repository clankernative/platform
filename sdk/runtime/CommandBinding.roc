import Context
import Operation
import Tx
import Write

CommandBinding :: { value : Operation }.{
	define : Write(a, b), (Context, a -> Tx(b)) -> CommandBinding
	define = |command, handle| { value: Operation.command(command.name(), command.input(), handle, command.output()) }

	bind : Write(a, b), (Context, a -> Tx(b)) -> CommandBinding
	bind = |command, program| define(command, program)

	operation : CommandBinding -> Operation
	operation = |binding| binding.value
}
