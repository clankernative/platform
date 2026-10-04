import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import NotificationHomeTypes

NotificationHome :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)

	handle : Context, NotificationHomeTypes.Input -> Query(NotificationHomeTypes.Output)
	handle = |_context, _input| Query.succeed({ title: "Notification configuration" })

	contract = {
		title: "Open notification configuration",
		usage: {
			purpose: "Open the event configuration editor.",
			use_when: ["Configuring an event message."],
			avoid_when: [],
			preconditions: [],
			effects: [],
			result: "The editor title, without app-scoped configuration data.",
		},
		inputs: {},
		outputs: { title: "Page title." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : NotificationHomeTypes.Input, output : NotificationHomeTypes.Output }, Str)
	example = |_| Ok({ input: {}, output: { title: "Notification configuration" } })

	verify_input : Str, U64 -> Try(NotificationHomeTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, NotificationHomeTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and output.title == "Notification configuration")
}
