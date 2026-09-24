import pf.Page
import pf.Cursor
import pf.PageSize
import ListLinksTypes
import Reads
import Templates

# Page routes take precedence over redirect routes: `/about` renders this page even
# when a link named `about` exists.
Routes :: [].{
	directory : Page(ListLinksTypes.Input)
	directory = Page.route({ title: "Go links", path: "/", template: Templates.directory }, Reads.list)
		.with_defaults({ after: Cursor.start, limit: PageSize.default })

	about : Page(ListLinksTypes.Input)
	about = Page.route({ title: "About", path: "/about", template: Templates.about }, Reads.list)
		.with_defaults({ after: Cursor.start, limit: PageSize.default })
}
