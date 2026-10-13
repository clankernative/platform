import ConnectionAccess
import Connection
import Observe

# Semantic declarations only. Requirement-specific execution APIs are generated
# separately; this module exposes no generic connection or token operations.
GoogleCalendar :: [].{
	# RFC3339 bounds in whole seconds with explicit offsets. The native adapter requires an
	# increasing window of at most 31 days and returns only a complete result.
	Window : { start : Str, end : Str }

	Event : { id : Str, summary : Str, start : Str, end : Str, all_day : Bool }

	ListOutcome : [Listed(List(Event)), Unavailable(Connection.Problem), InvalidWindow]

	read_events : ConnectionAccess
	read_events = ConnectionAccess.define("google_calendar_events", ["list_events"])

	read_and_create_events : ConnectionAccess
	read_and_create_events = ConnectionAccess.define("google_calendar_events", ["list_events", "create_event"])

	# Private transport used exclusively by generated requirement clients.
	list_events : Str, Str, Window -> Observe(ListOutcome)
	list_events = |registration, reference, window| Observe.capability(
		"google_calendar.list_events.v1",
		Json.to_str({ registration, reference, window }),
	).and_then(
		|raw| {
			parsed : Try(ListOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_calendar_list_outcome"))
		},
	)
}
