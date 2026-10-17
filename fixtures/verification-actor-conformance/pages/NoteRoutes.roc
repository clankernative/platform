import pf.Page
import Reads
import Templates

NoteRoutes :: [].{
	count : Page({})
	count = Page.route({ title: "Note count", path: "/", template: Templates.count }, Reads.count_notes)
		.with_defaults({})
}
