import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import InsertEntryTypes
import EntryView
import Data

InsertEntry :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.entries)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, InsertEntryTypes.Input -> Tx(EntryView.Value)
	handle = |context, input| Tx.create(
		Data.entries,
		{ owner: context.actor(), bucket: input.bucket, rank: input.rank, note: "before" },
	).map(EntryView.from_row)

	contract = {
		title: "Insert collection fixture entry",
		usage: {
			purpose: "Create an actor-owned entry for complete collection conformance.",
			use_when: ["Preparing visible and hidden collection rows."],
			avoid_when: ["Modifying an existing entry."],
			preconditions: [],
			effects: ["Creates one row and mandatory platform audit evidence."],
			result: "The created entry.",
		},
		inputs: { bucket: "Exact collection filter.", rank: "Descending collection order." },
		outputs: EntryView.fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : InsertEntryTypes.Input, output : EntryView.Value }, Str)
	example = |_| Ok({ input: { bucket: "keep", rank: 1 }, output: EntryView.sample({})? })

	verify_input : Str, U64 -> Try(InsertEntryTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ bucket: "keep", rank: 1 })

	verify_result : Str, EntryView.Value, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(next.entries.len() == old.entries.len() + 1 and next.entries.any(|row| row.id == output.id))
	}
}
