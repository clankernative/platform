import pf.Api
import Data

CollectionInvariants :: [].{
	entries = Api.invariant(Data.entries, "Every saved entry has an owner.", Data.snapshot, |state|
		state.entries.all(|row| !row.value.owner.trim().is_empty()))
}
