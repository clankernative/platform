import Input
import Output
import Operation

# Generated query handle, distinct from its app-owned Query-returning handler.
# Inferred from App.definition.operations; only generated code may call define.
Read(a, b) :: { key : Str, input : Input(a), output : Output(b), input_witness : List(a), output_witness : List(b) }.{
	define : Str, Input(a), Output(b) -> Read(a, b)
	define = |key, input, output| { key, input, output, input_witness: [], output_witness: [] }

	name : Read(a, b) -> Str
	name = |read| read.key

	input : Read(a, b) -> Input(a)
	input = |read| read.input

	output : Read(a, b) -> Output(b)
	output = |read| read.output

	metadata : Read(a, b) -> Operation.Metadata
	metadata = |read| { name: read.key, kind: "query", input_type: read.input.name(), output_type: read.output.name() }

	encode_input : Read(a, b), a -> Str
	encode_input = |read, value| read.input.encode(value)
}
