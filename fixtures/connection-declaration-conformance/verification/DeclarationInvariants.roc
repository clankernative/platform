import pf.Api
import Data

DeclarationInvariants :: [].{
	entries = Api.invariant(
		Data.entries,
		"Declaring connection intent never writes product data.",
		Data.snapshot,
		|state| state.entries.is_empty(),
	)
}
