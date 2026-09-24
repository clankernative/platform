import pf.Api
import Data

IdentityInvariants :: [].{
	entries =
		Api.invariant(
			Data.entries,
			"Every persisted entry retains a nonempty effective actor.",
			Data.snapshot,
			|state| state.entries.all(|row| !row.value.actor.is_empty()),
		)
}
