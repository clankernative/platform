import CreateLink
import DeleteLink
import VisitLink
import ListLinks
import MissingLink
import LinkErrors
import LinkInvariants
import Routes
import Redirects
import Demo

App :: [].{
	definition = {
		namespace: "go",
		operations: {
			create: CreateLink.definition,
			delete: DeleteLink.definition,
			visit: VisitLink.definition,
			list: ListLinks.definition,
			missing_link: MissingLink.definition,
		},
		pages: {
			links: Routes.directory.register(),
			about: Routes.about.register(),
			missing_link: Routes.missing_link.register(),
		},
		redirects: { prefixed: Redirects.prefixed.register(), bare: Redirects.bare.register() },
		properties: { links: LinkInvariants.links },
		errors: { invalid_link: LinkErrors.invalid_link, missing_link: LinkErrors.missing_link },
		examples: [Demo.definition],
		presentation: { stylesheet: "", script: "" },
	}
}
