import pf.Api
import Data

SetupInvariants :: [].{
	actor_states = Api.invariant(
		Data.actor_states,
		"Actor setup stages stay within the declared state machine.",
		Data.snapshot,
		|state| state.actor_states.all(|row| row.value.actor != "" and row.value.stage <= 2),
	)
}
