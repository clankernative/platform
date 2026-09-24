import pf.Api
import Data

LinkInvariants :: [].{
	links = Api.invariant(Data.links, "Every saved link has an owner.", Data.snapshot, |state|
		state.links.all(|row| !row.value.owner.trim().is_empty()))
}
