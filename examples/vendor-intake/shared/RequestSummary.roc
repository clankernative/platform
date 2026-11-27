import pf.Model
import Models

RequestSummary :: [].{
	Value : { id : U64, vendor : Str, status : Str, review_note : Str }

	fields =
		{
			id: "Immutable proposal number.",
			vendor: "Vendor name.",
			status: "pending, approved or returned.",
			review_note: "Recorded reason visible to requester.",
		}

	from_row : Model.Entity(Models.Request) -> Value
	from_row =
		|
			row,
		|
			{
				id: row.value.number,
				vendor: row.value.vendor,
				status: row.value.status,
				review_note: row.value.review_note,
			}
}
