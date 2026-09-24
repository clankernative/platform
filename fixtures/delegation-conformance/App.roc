import Who
import Forward
import RecordEntry
import IdentityInvariants

App :: [].{
	definition = {
		namespace: "delegation",
		operations: { who: Who.definition, forward: Forward.definition, record: RecordEntry.definition },
		pages: {},
		properties: { entries: IdentityInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
