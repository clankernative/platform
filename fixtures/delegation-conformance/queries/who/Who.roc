import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import WhoTypes
import IdentityView

Who :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)

	handle : Context, WhoTypes.Input -> Query(IdentityView.Value)
	handle = |context, _input| Query.from_try(Ok(IdentityView.from_context(context)))

	contract = {
		title: "Inspect effective request identity",
		usage: {
			purpose: "Expose the sealed context seen by a real Roc query for request-path conformance.",
			use_when: ["Checking direct, on-behalf-of and delegated request identities."],
			avoid_when: ["Choosing an identity or changing authority."],
			preconditions: [],
			effects: [],
			result: "The effective actor, verified requester, delegation rule and call chain.",
		},
		inputs: {},
		outputs: IdentityView.fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : WhoTypes.Input, output : IdentityView.Value }, Str)
	example = |_| Ok({ input: {}, output: IdentityView.sample({}) })

	verify_input : Str, U64 -> Try(WhoTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, IdentityView.Value, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and IdentityView.valid(output))
}
