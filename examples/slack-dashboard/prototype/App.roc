import SlackHistory
import RevisionInvariants

App :: [].{
	definition = {
		namespace: "channelhistory",
		operations: { history: SlackHistory.definition },
		pages: {},
		properties: { revisions: RevisionInvariants.revisions },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
