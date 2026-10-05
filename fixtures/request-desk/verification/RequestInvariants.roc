import pf.Api
import Data

RequestInvariants :: [].{
	ownership =
		Api.invariant(
			Data.requests,
			"Every request retains its effective owner.",
			Data.snapshot,
			|state| state.requests.all(|row| !row.value.owner.is_empty()),
		)
}
