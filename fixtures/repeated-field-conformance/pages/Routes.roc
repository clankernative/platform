import pf.Page
import pf.Cursor
import pf.PageSize
import ListThingsTypes
import Reads
import Templates

Routes :: [].{
	directory : Page(ListThingsTypes.Input)
	directory = Page.route({ title: "Things", path: "/", template: Templates.directory }, Reads.list)
		.with_defaults({ after: Cursor.start, limit: PageSize.default })
}
