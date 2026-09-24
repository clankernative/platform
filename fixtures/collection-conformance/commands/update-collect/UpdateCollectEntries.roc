import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.Cursor
import UpdateCollectEntriesTypes
import EntryView
import Data
import Selectors

UpdateCollectEntries :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.update(Data.entries, [Api.field(Selectors.entries_note)])]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, UpdateCollectEntriesTypes.Input -> Tx(EntryView.Result)
	handle = |_context, input| Tx.get(Data.entries, input.row_id)
		.and_then(|row| Tx.update(Data.entries, row, { ..row.value, note: input.note }))
		.and_then(|_| Tx.collect(EntryView.selection(input.bucket, input.after), input.maximum_rows))
		.map(|rows| EntryView.summarize(rows.map(EntryView.from_row)))

	contract = {
		title: "Update then collect in one transaction",
		usage: {
			purpose: "Prove complete collection failure rolls back a preceding write in the same transaction.",
			use_when: ["Checking collection atomicity and read-your-writes behavior."],
			avoid_when: ["Allowing a partial collection to justify a committed update."],
			preconditions: ["The target must be visible and writable; the collection bound is one through 256."],
			effects: ["Updates one note if the complete collection succeeds; overflow rolls back the update."],
			result: "Every matching visible entry including the update, or a platform failure with no committed write.",
		},
		inputs: {
			row_id: "The owned entry updated before collection.",
			bucket: "Exact collection filter.",
			maximum_rows: "Maximum complete collection size, from one through 256.",
			after: "Page cursor ignored by complete collection.",
			note: "Replacement note; failure must preserve the old note and revision.",
		},
		outputs: EntryView.result_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : UpdateCollectEntriesTypes.Input, output : EntryView.Result }, Str)
	example = |_| {
		row = EntryView.sample({})?
		Ok({
			input: { row_id: row.id, bucket: "keep", maximum_rows: 256, after: Cursor.start, note: "after" },
			output: EntryView.summarize([{ ..row, note: "after" }]),
		})
	}

	verify_input : Str, U64 -> Try(UpdateCollectEntriesTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row = Data.snapshot(snapshot)?.entries.first().map_err(|_| "insert an entry first")?
		Ok({ row_id: row.id, bucket: "keep", maximum_rows: 256, after: Cursor.start, note: "after" })
	}

	verify_result : Str, EntryView.Result, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			old.entries.len() == next.entries.len()
				and output.count == next.entries.keep_if(|row| row.value.bucket == "keep").len(),
		)
	}
}
