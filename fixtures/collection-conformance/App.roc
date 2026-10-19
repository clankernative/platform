import InsertEntry
import CollectEntries
import UpdateCollectEntries
import BatchUpdateEntries
import BatchLifecycle
import CollectionInvariants
import pf.Example
import Commands

App :: [].{
	definition = {
		namespace: "collections",
		operations: {
			insert: InsertEntry.definition,
			collect: CollectEntries.definition,
			update_collect: UpdateCollectEntries.definition,
			batch_update: BatchUpdateEntries.definition,
			batch_lifecycle: BatchLifecycle.definition,
		},
		pages: {},
		properties: { entries: CollectionInvariants.entries },
		errors: {
			batch_update_missing: BatchUpdateEntries.missing,
			batch_update_version_invalid: BatchUpdateEntries.invalid_version,
		},
		examples: [Example.define("entries", Ok([Example.Step.generated(Commands.insert, 0)]))],
		presentation: { stylesheet: "", script: "" },
	}
}
