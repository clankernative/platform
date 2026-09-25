import Input
import Output
import Operation
import Tx
import Model

# Generated command handle, distinct from its app-owned Tx-returning handler.
# Possessing a handle grants no authority; the host checks instance policy on invocation.
Write(a, b) :: { key : Str, input : Input(a), output : Output(b), input_witness : List(a), output_witness : List(b) }.{
	define : Str, Input(a), Output(b) -> Write(a, b)
	define = |key, input, output| { key, input, output, input_witness: [], output_witness: [] }

	name : Write(a, b) -> Str
	name = |write| write.key

	input : Write(a, b) -> Input(a)
	input = |write| write.input

	output : Write(a, b) -> Output(b)
	output = |write| write.output

	metadata : Write(a, b) -> Operation.Metadata
	metadata =
		|write| { name: write.key, kind: "command", input_type: write.input.name(), output_type: write.output.name() }

	defer_until : Write(a, b), Model(model), Model.Entity(model), a, I64 -> Tx({})
	defer_until =
		|
			command,
			model,
			target,
			payload,
			due,
		|
			Tx.invoke_deferral(
				command.key,
				command.input.name(),
				command.output.name(),
				model,
				target,
				command.input.encode(payload),
				due,
			)

	request : Write(a, b), Model(model), Model.Entity(model), a -> Tx({})
	request =
		|
			command,
			model,
			target,
			payload,
		|
			Tx.invoke_command(
				command.key,
				command.input.name(),
				command.output.name(),
				model,
				target,
				command.input.encode(payload),
			)

	encode_input : Write(a, b), a -> Str
	encode_input = |write, value| write.input.encode(value)
}
