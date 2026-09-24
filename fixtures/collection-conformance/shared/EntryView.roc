import pf.Model
import pf.Ref
import pf.RowVersion
import pf.Selection
import pf.Cursor
import pf.PageSize
import Models
import Data

EntryView :: [].{
	Value : { id : Ref(Models.Entry), version : RowVersion, owner : Str, bucket : Str, rank : I64, note : Str }

	Result : { count : U64, sequence : Str }

	fields = {
		id: "Stable entry identifier.",
		version: "Current row revision.",
		owner: "Actor who created the entry.",
		bucket: "Exact collection filter.",
		rank: "Descending collection order.",
		note: "Value used to prove transaction rollback.",
	}

	result_fields = {
		count: "Complete number of matching visible rows.",
		sequence: "Compact ordered JSON tokens containing every field for native conformance assertions.",
	}

	summarize : List(Value) -> Result
	summarize = |rows| {
		count: rows.len(),
		sequence: Json.to_str(
			rows.map(
				|row| Str.join_with(
					[
						row.id.to_str(),
						row.version.to_i64().to_str(),
						row.owner,
						row.bucket,
						row.rank.to_str(),
						row.note,
					],
					"|",
				),
			),
		),
	}

	from_row : Model.Entity(Models.Entry) -> Value
	from_row = |row| {
		id: row.id,
		version: row.version,
		owner: row.value.owner,
		bucket: row.value.bucket,
		rank: row.value.rank,
		note: row.value.note,
	}

	selection : Str, Cursor -> Selection(Models.Entry)
	selection = |bucket, after| Selection.filter(Data.entries, Data.entries_bucket_equal(bucket))
		.order([Data.entries_rank_desc]).paginate(after, PageSize.one)

	sample : {} -> Try(Value, Str)
	sample = |_| {
		id = Ref.from_str("ent_0000000000e008000000000000").map_err(|_| "invalid example entry")?
		Ok({ id, version: RowVersion.one, owner: "alice", bucket: "keep", rank: 1, note: "before" })
	}
}
