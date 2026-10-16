import pf.Api
import pf.Handler
import pf.Observe
import pf.Query
import pf.Context
import pf.Connection
import pf.GoogleCalendar
import pf.CollectionPage
import Connections
import ListEventsTypes

ListEvents :: [].{
	Output : { status : Str, events : CollectionPage(GoogleCalendar.Event) }

	definition = Api.query({
		handler: Handler.prepared(prepare, |_context, _input, output| Query.from_try(Ok(output))),
		contract: {
			title: "Read work calendar events",
			usage: {
				purpose: "Read a complete bounded window from the connected human's primary work calendar.",
				use_when: ["Checking upcoming calendar events."],
				avoid_when: ["Creating or changing calendar events."],
				preconditions: ["A verified human and an active admitted Calendar connection."],
				effects: [],
				result: "Events for the whole window or an explicit connection/provider problem.",
			},
			inputs: { start: "RFC3339 lower bound with an offset.", end: "RFC3339 upper bound, within 31 days." },
			outputs: {
				status: "ok, invalid_window, or a closed connection problem.",
				events: {
					description: "Complete bounded result. Problems return an empty collection.",
					fields: {
						items: {
							description: "Read-only provider event data.",
							each: {
								id: "Provider event identity.",
								summary: "Event title.",
								start: "RFC3339 timestamp or all-day date.",
								end: "Exclusive end timestamp or date.",
								all_day: "Whether the bounds are dates.",
							},
						},
						has_more: "Always false for a complete window.",
						next_after: "No public provider cursor.",
					},
				},
			},
			example: |_| Ok({
				input: { start: "2026-10-13T00:00:00Z", end: "2026-10-14T00:00:00Z" },
				output: empty("needs_connection"),
			}),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({ start: "2026-10-13T00:00:00Z", end: "2026-10-14T00:00:00Z" }),
			check: |before, output, after| Ok(
				before == after and !output.events.has_more() and output.events.next_after().is_start()
					and output.events.items().len() <= 100
						and [
							"ok",
							"invalid_window",
							"needs_connection",
							"reauth_required",
							"account_approval_required",
							"permission_denied",
							"binding_unavailable",
							"provider_unavailable",
							"capacity_deferred",
						]
							.contains(output.status)
							and (output.status == "ok" or output.events.items().is_empty()),
			),
		},
	})

	empty : Str -> Output
	empty = |status| { status, events: CollectionPage.empty({}) }

	problem : Connection.Problem -> Str
	problem = |value| match value {
		NeedsConnection => "needs_connection"
		ReauthRequired => "reauth_required"
		AccountApprovalRequired => "account_approval_required"
		PermissionDenied => "permission_denied"
		BindingUnavailable => "binding_unavailable"
		ProviderUnavailable => "provider_unavailable"
		CapacityDeferred => "capacity_deferred"
	}

	prepare : Context, ListEventsTypes.Input -> Observe(Output)
	prepare = |_context, input| (Connections.calendar.resolve)({}).and_then(
		|resolution| match resolution {
			Unavailable(reason) => Observe.value(empty(problem(reason)))
			Available(connection) => (Connections.calendar
				.list_events)(connection, { start: input.start, end: input.end })
				.map(
					|outcome| match outcome {
						Listed(events) => { status: "ok", events: CollectionPage.complete(events) }
						Unavailable(reason) => empty(problem(reason))
						InvalidWindow => empty("invalid_window")
					},
				)
		},
	)
}
