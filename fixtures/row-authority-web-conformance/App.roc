import Storage
import CreateLink
import EditLink
import ListLinks
import GetLink
import Routes
import LinkInvariants
import Demo

App :: [].{
	definition = {
		namespace: "links",
		storage: Storage.definition,
		operations: {
			create: CreateLink.definition,
			edit: EditLink.definition,
			list: ListLinks.definition,
			detail: GetLink.definition,
		},
		pages: { links: Routes.directory.register(), link: Routes.details.register() },
		properties: { links: LinkInvariants.links },
		errors: { rejected_title: CreateLink.rejected_title },
		examples: [Demo.definition],
		presentation: { stylesheet: "app.css", script: "" },
	}
}
