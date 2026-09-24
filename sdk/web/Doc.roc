import Read
import Write
import Input
import Output

# Optional prose and typed examples. The host derives and validates all schemas.
Doc :: [].{
	Field : { path : Str, description : Str }

	Entry : {
		operation : Str,
		input_type : Str,
		output_type : Str,
		summary : Str,
		description : Str,
		response_description : Str,
		inputs : List(Field),
		outputs : List(Field),
		request_example : Str,
		response_example : Str,
		deprecated : Bool,
	}

	Operation(a, b) :: { entry : Entry, input : Input(a), output : Output(b) }.{
		description : Operation(a, b), Str -> Operation(a, b)
		description = |doc, text| { ..doc, entry: { ..doc.entry, description: text } }

		input : Operation(a, b), Str, Str -> Operation(a, b)
		input =
			|
				doc,
				path,
				prose,
			| { ..doc, entry: { ..doc.entry, inputs: doc.entry.inputs.append({ path, description: prose }) } }

		output : Operation(a, b), Str, Str -> Operation(a, b)
		output =
			|
				doc,
				path,
				prose,
			| { ..doc, entry: { ..doc.entry, outputs: doc.entry.outputs.append({ path, description: prose }) } }

		response : Operation(a, b), Str -> Operation(a, b)
		response = |doc, text| { ..doc, entry: { ..doc.entry, response_description: text } }

		request_example : Operation(a, b), a -> Operation(a, b)
		request_example = |doc, value| { ..doc, entry: { ..doc.entry, request_example: doc.input.encode(value) } }

		response_example : Operation(a, b), b -> Operation(a, b)
		response_example = |doc, value| { ..doc, entry: { ..doc.entry, response_example: doc.output.encode(value) } }

		deprecated : Operation(a, b) -> Operation(a, b)
		deprecated = |doc| { ..doc, entry: { ..doc.entry, deprecated: Bool.True } }

		register : Operation(a, b) -> Entry
		register = |doc| doc.entry
	}

	query : Read(a, b), Str -> Operation(a, b)
	query = |read, summary| make(read.name(), read.input(), read.output(), summary)

	command : Write(a, b), Str -> Operation(a, b)
	command = |write, summary| make(write.name(), write.input(), write.output(), summary)

	make : Str, Input(a), Output(b), Str -> Operation(a, b)
	make = |operation, input, output, summary| {
		input,
		output,
		entry: {
			operation,
			input_type: input.name(),
			output_type: output.name(),
			summary,
			description: "",
			response_description: "",
			inputs: [],
			outputs: [],
			request_example: "",
			response_example: "",
			deprecated: Bool.False,
		},
	}

	encode : Try(List(Entry), Str) -> Str
	encode = |result| Json.to_str(
		match result {
			Ok(entries) => { entries, error: "" }
			Err(error) => { entries: [], error }
		},
	)
}
