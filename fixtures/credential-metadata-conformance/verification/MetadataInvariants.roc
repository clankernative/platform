import pf.Api
import Data

MetadataInvariants :: [].{
	entries =
		Api.invariant(
			Data.entries,
			"Product registrations contain only public credential references.",
			Data.snapshot,
			|
				state,
			|
				state
					.entries
					.all(
						|row| row.value.note.starts_with("cr1_clients_") or row.value.note.starts_with("cr1_personal_"),
					),
		)
}
