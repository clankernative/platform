import InsertEntry
import CollectEntries
import UpdateCollectEntries
import CollectionInvariants

App :: [].{
	definition = {
		namespace: "collections",
		operations: {
			insert: InsertEntry.definition,
			collect: CollectEntries.definition,
			update_collect: UpdateCollectEntries.definition,
		},
		pages: {},
		properties: { entries: CollectionInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
