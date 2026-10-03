import pf.ConnectionRequirement
import pf.GoogleCalendar

CalendarConnection :: [].{
	requirement = ConnectionRequirement.for_current_human({
		id: "work_calendar",
		revision: 1,
		access: GoogleCalendar.read_events,
		account: ConnectionRequirement.company_account,
		usage: "Read your work calendar events for the installation qualification canary.",
	})
}
