import pf.Page
import Reads
import Templates
import RequestHomeTypes

RequestRoutes :: [].{
	home : Page(RequestHomeTypes.Input)
	home = Page.route({ title: "Request stock", path: "/", template: Templates.requests }, Reads.home).with_defaults({})
}
