import pf.Api
import Commands
import CreateLinkTypes
import VisitLinkTypes

LinkErrors :: [].{
	invalid_link = Api.error({
		description: "A link needs a name of lowercase letters, digits, dashes and slashes, optionally ending in /%s, and a destination.",
		recovery: "Choose a valid name and supply a destination.",
		verification: |_| Api.failed_command(Commands.create, |_snapshot, _seed| Ok({ name: "", url: "" })),
	})

	missing_link = Api.error({
		description: "No active link or wildcard matches this address.",
		recovery: "Check the link name, or create the link.",
		verification: |_| Api.failed_command(Commands.visit, |_snapshot, _seed| Ok({ path: "no-such-link-anywhere" })),
	})
}
