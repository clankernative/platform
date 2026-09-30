import pf.ConnectionRequirement
import pf.GoogleCalendar

CalendarConnection :: [].{
	calendar = ConnectionRequirement.for_current_human({
		id: "work_calendar",
		revision: 1,
		access: GoogleCalendar.read_and_create_events,
		account: ConnectionRequirement.company_account,
		usage: "Find available time and add meetings to your work calendar.",
	})

	availability = ConnectionRequirement.for_current_human({
		id: "availability",
		revision: 1,
		access: GoogleCalendar.read_events,
		account: ConnectionRequirement.explicit_external_account,
		usage: "Read events from the account you explicitly approve.",
	})
}
