import pf.Api
import pf.Handler
import pf.Query
import pf.Context
import RequestHomeTypes

RequestHome :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)

	handle : Context, RequestHomeTypes.Input -> Query(RequestHomeTypes.Output)
	handle = |_context, _input| Query.from_try(Ok({ title: "Request stock" }))

	contract = {
		title: "Request stock",
		usage: {
			purpose: "Open the stock request form.",
			use_when: ["Requesting a reservation."],
			avoid_when: [],
			preconditions: [],
			effects: [],
			result: "The request form title.",
		},
		inputs: {},
		outputs: { title: "The page title." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : RequestHomeTypes.Input, output : RequestHomeTypes.Output }, Str)
	example = |_| Ok({ input: {}, output: { title: "Request stock" } })

	verify_input : Str, U64 -> Try(RequestHomeTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, RequestHomeTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and output.title == "Request stock")
}
