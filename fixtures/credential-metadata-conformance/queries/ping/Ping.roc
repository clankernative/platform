import pf.Api
import pf.Handler
import pf.Query
import pf.Context
import PingTypes

Ping :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract: {
			title: "Credential root conformance",
			usage: {
				purpose: "Declare a bounded local credential root.",
				use_when: ["Checking the local credential authority root."],
				avoid_when: [],
				preconditions: [],
				effects: [],
				result: "Readiness.",
			},
			inputs: {},
			outputs: { ready: "Always true." },
			example: |_| Ok({ input: {}, output: { ready: Bool.True } }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({}),
			check: |before, output, after| Ok(before == after and output.ready),
		},
	}).credential_ready()

	handle : Context, PingTypes.Input -> Query({ ready : Bool })
	handle = |_context, _input| Query.from_try(Ok({ ready: Bool.True }))
}
