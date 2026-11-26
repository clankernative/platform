import pf.Api
import pf.CollectionPage
import pf.Context
import pf.Handler
import pf.Observe
import pf.Query
import pf.Resource
import pf.Slack
import SlackHistoryTypes

SlackHistory :: [].{
	Output : { channel : Str, messages : CollectionPage(Slack.Message), has_more : Bool }

	definition = Api.query({
		audience: Employees,
		handler: Handler.prepared(prepare, handle),
		contract,
		verification: { input: |_snapshot, _seed| Ok({}), check: verify_result },
	}).observes("slack.read.v1")

	prepare : Context, SlackHistoryTypes.Input -> Observe(Slack.History)
	prepare = |context, _input| Resource.bind(context, "dashboard_channel").and_then(|channel| Slack.read(channel, 20))

	handle : Context, SlackHistoryTypes.Input, Slack.History -> Query(Output)
	handle =
		|
			_context,
			_input,
			history,
		|
			Query.succeed({
				channel: history.channel,
				messages: CollectionPage.complete(history.messages),
				has_more: history.has_more,
			})

	contract = {
		title: "Read recent Slack messages",
		usage: {
			purpose: "Read up to 20 recent messages in the dashboard's assigned channel.",
			use_when: ["Refreshing the dashboard as the current viewer."],
			avoid_when: [],
			preconditions: ["The viewer has an active read grant for the dashboard channel."],
			effects: [],
			result: "The channel and messages in newest-first order.",
		},
		inputs: {},
		outputs: {
			channel: "The assigned Slack channel ID.",
			messages: {
				description: "Up to 20 recent messages.",
				fields: {
					items: {
						description: "Messages ordered newest first.",
						each: { timestamp: "Slack message timestamp.", text: "Message text." },
					},
					has_more: "False for the complete bounded result.",
					next_after: "Empty cursor for the complete bounded result.",
				},
			},
			has_more: "Whether the channel has older messages.",
		},
		example: |
			_,
		|
			Ok({
				input: {},
				output: {
					channel: "C123",
					messages: CollectionPage.complete([{ timestamp: "1767225600.000001", text: "Ready for review." }]),
					has_more: Bool.False,
				},
			}),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, history, after| Ok(
		before == after and !history.channel.is_empty() and history.messages.items().len() <= 20
			and !history.messages.has_more() and history.messages.next_after().is_start()
				and history.messages.items().all(|message| !message.timestamp.is_empty()),
	)
}
