import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import pf.Cursor
import CollectEntriesTypes
import EntryView
import Data

CollectEntries :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, CollectEntriesTypes.Input -> Query(EntryView.Result)
	handle = |_context, input| Query.collect(EntryView.selection(input.bucket, input.after), input.maximum_rows)
		.map(|rows| EntryView.summarize(rows.map(EntryView.from_row)))

	contract = {
		title: "Collect every visible matching entry",
		usage: {
			purpose: "Read a complete bounded collection while preserving row authority, filter and order.",
			use_when: ["A decision requires every matching visible row."],
			avoid_when: ["Returning an intentionally partial page."],
			preconditions: ["The platform requires a bound from one through 256 and rejects overflow."],
			effects: [],
			result: "Every matching visible entry or a platform capacity failure; never a truncated list.",
		},
		inputs: {
			bucket: "Exact collection filter.",
			maximum_rows: "Maximum complete collection size, from one through 256.",
			after: "A page cursor that complete collection must ignore when restarting from the beginning.",
		},
		outputs: EntryView.result_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : CollectEntriesTypes.Input, output : EntryView.Result }, Str)
	example = |_| Ok({
		input: { bucket: "keep", maximum_rows: 256, after: Cursor.start },
		output: EntryView.summarize([EntryView.sample({})?]),
	})

	verify_input : Str, U64 -> Try(CollectEntriesTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ bucket: "keep", maximum_rows: 256, after: Cursor.start })

	verify_result : Str, EntryView.Result, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		state = Data.snapshot(before)?
		Ok(before == after and output.count == state.entries.keep_if(|row| row.value.bucket == "keep").len())
	}
}
