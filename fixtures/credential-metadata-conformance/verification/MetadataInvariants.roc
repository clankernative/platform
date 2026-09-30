import pf.Api
import Data

MetadataInvariants :: [].{
	entries =
		Api.invariant(
			Data.entries,
			"Metadata queries never write application rows.",
			Data.snapshot,
			|state| state.entries.is_empty(),
		)
}
