import Seed
import Move
import ListDeals
import RelationalInvariants
import Demo

App :: [].{
	definition = {
		namespace: "deals",
		operations: { seed: Seed.definition, move: Move.definition, list: ListDeals.definition },
		pages: {},
		properties: {
			deals: RelationalInvariants.relationships,
			stages: RelationalInvariants.counts,
			history: RelationalInvariants.history,
		},
		errors: { already_initialized: Seed.already_initialized, stale_revision: Move.stale_revision },
		examples: [Demo.definition],
		presentation: { stylesheet: "", script: "" },
	}
}
