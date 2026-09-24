import Storage
import InsertEntry
import CollectEntries
import UpdateCollectEntries
import CollectionInvariants

App :: [].{
	definition = {
		namespace: "collections",
		storage: Storage.definition,
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
