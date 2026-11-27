import SaveRevision
import ReadRevision
import SlackHistory
import RevisionInvariants
import Demo

App :: [].{
	definition = {
		namespace: "slackdashboard",
		operations: {
			history: SlackHistory.definition,
			revision: ReadRevision.definition,
			save_revision: SaveRevision.definition,
		},
		pages: {},
		properties: { revisions: RevisionInvariants.revisions },
		errors: { invalid_html: SaveRevision.invalid_html, missing_revision: ReadRevision.missing_revision },
		examples: [Demo.definition],
		presentation: { stylesheet: "", script: "" },
	}
}
