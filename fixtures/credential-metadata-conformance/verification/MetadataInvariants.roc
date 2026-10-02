import pf.Api
import Data

MetadataInvariants :: [].{
	use_receipts = Api.invariant(
		Data.use_receipts,
		"Product use receipts carry public labels.",
		Data.snapshot,
		|state| state.use_receipts.all(|row| row.value.note.starts_with("use_")),
	)

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
