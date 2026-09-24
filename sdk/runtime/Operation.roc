import Wire
import Context
import Tx
import Query
import Input
import Output

Operation :: { metadata : Metadata, execute : Wire.Context, Str -> Tx(Str) }.{
	Metadata : { name : Str, kind : Str, input_type : Str, output_type : Str }

	command : Str, Input(input), (Context, input -> Tx(output)), Output(output) -> Operation
	command = |name, input_contract, handle, output_contract| {
		metadata: { name, kind: "command", input_type: input_contract.name(), output_type: output_contract.name() },
		execute: |
			context,
			raw,
		|
			Tx.from_host(input_contract.decode(raw))
				.and_then(|input| handle(Context.from_wire(context), input))
				.map(|value| output_contract.encode(value)),
	}

	query : Str, Input(input), (Context, input -> Query(output)), Output(output) -> Operation
	query = |name, input_contract, handle, output_contract| {
		metadata: { name, kind: "query", input_type: input_contract.name(), output_type: output_contract.name() },
		execute: |
			context,
			raw,
		|
			Tx.from_host(input_contract.decode(raw))
				.and_then(|input| handle(Context.from_wire(context), input).as_transaction())
				.map(|value| output_contract.encode(value)),
	}

	# Preparation is interpreted outside the local query transaction.
	prepared_query : Str, Input(input), (Context, input -> Tx(output)), Output(output) -> Operation
	prepared_query = |name, input_contract, program, output_contract| {
		metadata: { name, kind: "query", input_type: input_contract.name(), output_type: output_contract.name() },
		execute: |context, raw| Tx.from_host(input_contract.decode(raw))
			.and_then(|input| program(Context.from_wire(context), input))
			.map(|value| output_contract.encode(value)),
	}

	metadata : Operation -> Metadata
	metadata = |operation| operation.metadata

	name : Operation -> Str
	name = |operation| operation.metadata.name

	execute : Operation, Wire.Context, Str -> Tx(Str)
	execute = |operation, context, raw| (operation.execute)(context, raw)
}
