import pf.Page
import ManageKeysTypes
import Reads
import Templates

Routes :: [].{
	keys : Page(ManageKeysTypes.Input)
	keys = Page.route({ title: "Credential keys", path: "/", template: Templates.keys }, Reads.manage)
		.with_defaults({})
}
