import CalendarConnection
import Ping
import DeclarationInvariants

App :: [].{
	definition = {
		namespace: "connection_declaration",
		connections: { calendar: CalendarConnection.calendar, availability: CalendarConnection.availability },
		operations: { ping: Ping.definition },
		pages: {},
		properties: { entries: DeclarationInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
