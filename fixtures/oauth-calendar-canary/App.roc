import CalendarConnection
import InspectIntent
import CanaryInvariants

App :: [].{
	definition = {
		namespace: "oauthcalendar",
		connections: { calendar: CalendarConnection.requirement },
		operations: { inspect: InspectIntent.definition },
		pages: {},
		properties: { entries: CanaryInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
