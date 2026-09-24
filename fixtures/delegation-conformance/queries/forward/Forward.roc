import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import pf.Observe
import pf.Resource
import pf.Delegate
import ForwardTypes
import IdentityView

Forward :: [].{
	Output : { identity : IdentityView.Value, answer : Str }

	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})

	prepare : Context, ForwardTypes.Input -> Observe(Str)
	prepare = |context, _input| Resource.bind(context, "delegation").and_then(|resource| Delegate.query(resource, "{}"))

	handle : Context, ForwardTypes.Input, Str -> Query(Output)
	handle = |context, _input, answer| Query.from_try(Ok({ identity: IdentityView.from_context(context), answer }))

	contract = {
		title: "Read another application's identity",
		usage: {
			purpose: "Exercise the admitted app.query.v1 resource with the host's effective actor.",
			use_when: [
				"Checking actor inheritance, immediate caller and recorded observations across an app boundary.",
			],
			avoid_when: ["Writing to another app or selecting a different actor for the callee."],
			preconditions: ["An operator binds delegation to a reviewed query and grants the effective actor access."],
			effects: [],
			result: "This query's sealed context and the callee's recorded JSON response.",
		},
		inputs: {},
		outputs: {
			identity: { description: "Sealed context of the calling query.", fields: IdentityView.fields },
			answer: "Unmodified JSON response from the query pinned by the delegation resource.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : ForwardTypes.Input, output : Output }, Str)
	example = |_| Ok({ input: {}, output: { identity: IdentityView.sample({}), answer: "{}" } })

	verify_input : Str, U64 -> Try(ForwardTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result =
		|
			before,
			output,
			after,
		| Ok(before == after and IdentityView.valid(output.identity) and !output.answer.is_empty())
}
