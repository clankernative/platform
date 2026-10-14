import pf.Api
import Data
import FixtureAccess

NoteInvariants :: [].{
	notes = Api.invariant(
		Data.notes,
		"Only the fixture operator owns saved notes.",
		Data.snapshot,
		|state| state.notes.all(|row| FixtureAccess.authorized(row.value.owner)),
	)
}
