import Write

# Pure command inputs for platform-owned development fixtures. A handle grants
# no authority; the host validates the operation and runs its usual transaction.
Example :: { name : Str, steps : Try(List(Step), Str) }.{
	StepMode : [Command, Generated]

	Step :: { mode : StepMode, operation : Str, payload : Str }.{
		command : Write(a, b), a -> Step
		command = |write, input| {
			mode: Command,
			operation: write.name(),
			payload: write.encode_input(input),
		}

		generated : Write(a, b), U64 -> Step
		generated = |write, seed| {
			mode: Generated,
			operation: write.name(),
			payload: seed.to_str(),
		}

		metadata : Step -> { kind : Str, operation : Str, payload : Str }
		metadata = |step| {
			kind: match step.mode {
				Command => "command"
				Generated => "generated"
			},
			operation: step.operation,
			payload: step.payload,
		}
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
