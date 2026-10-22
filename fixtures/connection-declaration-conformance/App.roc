import CalendarConnection
import Ping
import DirectoryUser
import DeclarationInvariants

App :: [].{
	definition = {
		namespace: "connection_declaration",
		connections: { calendar: CalendarConnection.calendar, availability: CalendarConnection.availability },
		operations: { ping: Ping.definition, directory_user: DirectoryUser.definition },
		pages: {},
		properties: { entries: DeclarationInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
