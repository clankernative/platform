import pf.Page
import Reads
import Templates
import NotificationHomeTypes

NotificationRoutes :: [].{
	home : Page(NotificationHomeTypes.Input)
	home =
		Page.route({ title: "Notification configuration", path: "/", template: Templates.notifications }, Reads.home)
			.with_defaults({})
}
