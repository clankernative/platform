import AInvalidate
import BRead
import ConfigureFailure
import PrepareFirst
import PrepareSecond
import SetupInvariants

App :: [].{
	definition = {
		namespace: "verification_setup",
		operations: {
			a_invalidate: AInvalidate.definition,
			b_read: BRead.definition,
			configure_failure: ConfigureFailure.definition,
			prepare_first: PrepareFirst.definition,
			prepare_second: PrepareSecond.definition,
		},
		pages: {},
		properties: { actor_states: SetupInvariants.actor_states },
		errors: {
			read_unprepared: BRead.read_unprepared,
			prepare_unready: PrepareSecond.prepare_unready_error,
		},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
