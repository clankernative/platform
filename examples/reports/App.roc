import Storage
import SubmitReport
import ReviseReport
import ListReports
import GetReport
import AnalyzeReport
import NotifyReady
import SweepReports
import Schedules
import Routes
import ReportInvariants
import Demo

App :: [].{
	definition = {
		namespace: "reports",
		storage: Storage.definition,
		operations: {
			submit: SubmitReport.definition,
			revise: ReviseReport.definition,
			analyze: AnalyzeReport.definition,
			notify: NotifyReady.definition,
			sweep: SweepReports.definition,
			list: ListReports.definition,
			detail: GetReport.definition,
		},
		schedules: { sweep: Schedules.sweep.register() },
		pages: { reports: Routes.directory.register(), report: Routes.details.register() },
		properties: { reports: ReportInvariants.reports },
		errors: {},
		examples: [Demo.definition],
		presentation: { stylesheet: "app.css", script: "" },
	}
}
