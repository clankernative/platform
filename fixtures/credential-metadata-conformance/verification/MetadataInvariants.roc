import pf.Api
import Data

MetadataInvariants :: [].{
	key_receipts = Api.invariant(
		Data.key_receipts,
		"Lifecycle receipts contain public identity and positive management revisions.",
		Data.snapshot,
		|
			state,
		|
			state
				.key_receipts
				.all(
					|
						row,
					|
						row.value.revision
							> 0
							and !row.value.head.is_empty()
								and row.value.lineage.starts_with("cr1_${row.value.family}_"),
				),
	)

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
