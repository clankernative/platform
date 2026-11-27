import pf.Api
import Data

RevisionInvariants :: [].{
	revisions = Api.invariant(
		Data.revisions,
		"Every saved revision is an original row with a distinct positive number, an author and nonblank HTML.",
		Data.snapshot,
		|state| state.revisions.all(
			|row| {
				row.version.to_u64() == 1 and row.value.number > 0 and row.value.number <= state.revisions.len()
					and !row.value.author.is_empty() and !row.value.html.trim().is_empty()
						and state.revisions.keep_if(|other| other.value.number == row.value.number).len() == 1
			},
		),
	)
}
