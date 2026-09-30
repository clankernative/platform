import ConnectionAccess

# Semantic declarations only. Requirement-specific execution APIs are generated
# separately; this module exposes no generic connection or token operations.
GoogleCalendar :: [].{
	read_events : ConnectionAccess
	read_events = ConnectionAccess.define("google_calendar_events", ["list_events"])

	read_and_create_events : ConnectionAccess
	read_and_create_events = ConnectionAccess.define("google_calendar_events", ["list_events", "create_event"])
}
