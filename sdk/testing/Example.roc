import Write

# Pure command inputs for platform-owned development fixtures. A handle grants
# no authority; the host validates the operation and runs its usual transaction.
Example :: { name : Str, steps : Try(List(Step), Str) }.{
	Step :: { operation : Str, input : Str }.{
		command : Write(a, b), a -> Step
		command = |command, input| { operation: command.name(), input: command.encode_input(input) }

		metadata : Step -> { operation : Str, input : Str }
		metadata = |step| { operation: step.operation, input: step.input }
	}

	define : Str, Try(List(Step), Str) -> Example
	define = |name, steps| { name, steps }

	encode : List(Example) -> Str
	encode = |examples| Json.to_str(
		examples.map(
			|example| match example.steps {
				Ok(steps) => { name: example.name, steps: steps.map(Step.metadata), error: "" }
				Err(error) => { name: example.name, steps: [], error }
			},
		),
	)
}
