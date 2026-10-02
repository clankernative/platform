import Who
import RecordEntry
import History
import IdentityInvariants

App :: [].{
	definition = {
		namespace: "peer_identity",
		operations: { who: Who.definition, record: RecordEntry.definition, history: History.definition },
		pages: {},
		properties: { entries: IdentityInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
