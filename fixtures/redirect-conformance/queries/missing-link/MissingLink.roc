import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import VisitLinkTypes

MissingLink :: [].{
	View : { name : Str }

	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, VisitLinkTypes.Input -> Query(View)
	handle = |_context, input| Query.succeed({ name: input.path })

	contract = {
		title: "Suggest creating a missing link",
		usage: {
			purpose: "Present the unresolved logical path in an app-owned create form.",
			use_when: ["A redirect reported the declared missing-link failure."],
			avoid_when: ["Resolving or creating a link."],
			preconditions: [],
			effects: [],
			result: "The requested name, without a mutation.",
		},
		inputs: { path: "Decoded logical path from the visit route." },
		outputs: { name: "Name to prefill in the create form." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : VisitLinkTypes.Input, output : View }, Str)
	example = |_| Ok({ input: { path: "new-link" }, output: { name: "new-link" } })

	verify_input : Str, U64 -> Try(VisitLinkTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ path: "new-link" })

	verify_result : Str, View, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and output.name == "new-link")
}
