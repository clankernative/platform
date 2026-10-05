import pf.Api
import Data

CanaryInvariants :: [].{
	entries = Api.invariant(
		Data.entries,
		"Inspecting the GitLab canary intent never writes product data.",
		Data.snapshot,
		|state| state.entries.is_empty(),
	)
}
