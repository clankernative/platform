import Who
import Forward
import RecordEntry
import History
import IdentityInvariants
import SendEntry
import ReceiptStatus

App :: [].{
	definition = {
		namespace: "delegation",
		operations: {
			who: Who.definition,
			forward: Forward.definition,
			record: RecordEntry.definition,
			send: SendEntry.definition,
			status: ReceiptStatus.definition,
			history: History.definition,
		},
		pages: {},
		properties: { entries: IdentityInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
