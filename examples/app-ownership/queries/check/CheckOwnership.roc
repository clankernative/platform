import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import CheckOwnershipTypes
import Ownership
import Data

CheckOwnership :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	}).cross_app({ version: 1 })

	handle : Context, CheckOwnershipTypes.Input -> Query(CheckOwnershipTypes.Output)
	handle = |context, input| {
		if !Ownership.valid_app_id(input.app_id) or !Ownership.valid_principal(context.actor()) {
			Query.succeed({ app_id: input.app_id, allowed: Bool.False })
		} else {
			Query.find(Ownership.selection(input.app_id, context.actor())).map(
				|found| {
					app_id: input.app_id,
					allowed: match found {
						Some(row) => row.value.active
						None => Bool.False
					},
				},
			)
		}
	}

	contract = {
		title: "Check current app ownership",
		usage: {
			purpose: "Check the inherited human's direct ownership of an app.",
			use_when: ["Authorizing an app-scoped business operation."],
			avoid_when: ["Authorizing group membership without a directory provider."],
			preconditions: ["The instance permits this ownership query."],
			effects: [],
			result: "A fresh direct ownership decision for the requested app.",
		},
		inputs: { app_id: "The business app identifier. The host supplies the human identity." },
		outputs: {
			app_id: "The requested app identifier.",
			allowed: "Whether the inherited human is an active direct owner.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : CheckOwnershipTypes.Input, output : CheckOwnershipTypes.Output }, Str)
	example = |_| Ok({ input: { app_id: "demo" }, output: { app_id: "demo", allowed: Bool.True } })

	verify_input : Str, U64 -> Try(CheckOwnershipTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ app_id: "demo" })

	verify_result : Str, CheckOwnershipTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		state = Data.snapshot(before)?
		Ok(
			before == after and output.app_id == "demo" and (
				!output.allowed or state.ownerships.any(
					|row| row.value.app_id == output.app_id and row.value.active,
				)
			),
		)
	}
}
