import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Query
import ImportedContracts
import RequestProgressTypes

RequestProgress :: [].{
	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})

	prepare : Context, RequestProgressTypes.Input -> Observe(Str)
	prepare =
		|
			_context,
			input,
		| ImportedContracts.stock_ledger_reserve_status({ id: input.receipt }).map(
			|status| match status {
				Pending => "pending"
				Success => "success"
				Refused => "refused"
				Blocked => "blocked"
				Unknown => "unknown"
			},
		)

	handle : Context, RequestProgressTypes.Input, Str -> Query(RequestProgressTypes.Output)
	handle = |_context, _input, status| Query.from_try(Ok({ status: status }))

	contract = {
		title: "Inspect a stock request",
		usage: {
			purpose: "Inspect the receiver's authorized business outcome.",
			use_when: ["Following an accepted request."],
			avoid_when: ["Assuming unknown means not applied."],
			preconditions: ["Current receipt access."],
			effects: [],
			result: "Receiver progress without its private result payload.",
		},
		inputs: { receipt: "The accepted stock reservation receipt." },
		outputs: { status: "Pending, success, refused, blocked or unknown." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : RequestProgressTypes.Input, output : RequestProgressTypes.Output }, Str)
	example = |_| Ok({ input: { receipt: "rcp_${Str.repeat("0", 64)}" }, output: { status: "unknown" } })

	verify_input : Str, U64 -> Try(RequestProgressTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ receipt: "rcp_${Str.repeat("0", 64)}" })

	verify_result : Str, RequestProgressTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and !output.status.is_empty())
}
