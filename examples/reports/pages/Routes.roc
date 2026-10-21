import pf.Page
import pf.Cursor
import pf.PageSize
import ListReportsTypes
import GetReportTypes
import Reads
import Templates

# Routes bind generated read and template handles; HTML remains under ui/pages/.
Routes :: [].{
	directory : Page(ListReportsTypes.Input)
	directory = Page.route({ title: "Reports", path: "/", template: Templates.directory }, Reads.list)
		.with_defaults({ after: Cursor.start, limit: PageSize.default })
		.live()

	details : Page(GetReportTypes.Input)
	details = Page.route({ title: "Report", path: "/reports/{report_id}", template: Templates.details }, Reads.detail)
		.live_refresh_every(1000.U64)
}
