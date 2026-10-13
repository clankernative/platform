import CalendarConnection
import InspectIntent
import ListEvents
import CanaryInvariants

App :: [].{
	definition = {
		namespace: "oauthcalendar",
		connections: { calendar: CalendarConnection.requirement },
		operations: { inspect: InspectIntent.definition, list_events: ListEvents.definition },
		pages: {},
		properties: { entries: CanaryInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
