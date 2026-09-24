import pf.Page
import pf.Cursor
import pf.PageSize
import ListLinksTypes
import GetLinkTypes
import Reads
import Templates

Routes :: [].{
	directory : Page(ListLinksTypes.Input)
	directory = Page.route(
		{ title: "Owned links", path: "/", template: Templates.directory },
		Reads.list,
	).with_defaults({ after: Cursor.start, limit: PageSize.default })

	details : Page(GetLinkTypes.Input)
	details = Page.route(
		{ title: "Edit link", path: "/links/{link_id}", template: Templates.details },
		Reads.detail,
	)
}
