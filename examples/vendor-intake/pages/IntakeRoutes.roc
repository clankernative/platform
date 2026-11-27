import pf.Page
import pf.Cursor
import Reads
import Templates
import ReviewQueueTypes
import ProposalTypes
import MyRequestsTypes

IntakeRoutes :: [].{
	intake : Page(MyRequestsTypes.Input)
	intake =
		Page.route({ title: "Vendor intake", path: "/", template: Templates.intake }, Reads.my_requests)
			.with_defaults({})

	review : Page(ReviewQueueTypes.Input)
	review =
		Page.route({ title: "Vendor review queue", path: "/review", template: Templates.queue }, Reads.review_queue)
			.with_defaults({ after: Cursor.start })

	proposal : Page(ProposalTypes.Input)
	proposal =
		Page.route({ title: "Vendor proposal", path: "/review/{id}", template: Templates.proposal }, Reads.proposal)
}
