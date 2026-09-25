import pf.Api
import Data

LinkInvariants :: [].{
	links = Api.invariant(
		Data.links,
		"Every link has a nonempty name and destination.",
		Data.snapshot,
		|state| state.links.all(|row| !row.value.name.is_empty() and !row.value.url.is_empty()),
	)
}
