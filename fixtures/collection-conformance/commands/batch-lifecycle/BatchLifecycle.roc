import pf.Api
import pf.Context
import pf.Handler
import pf.Tx
import Data
import Selectors
import EntryView
import BatchLifecycleTypes

BatchLifecycle :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.create(Data.entries),
			Api.update(Data.entries, [Api.field(Selectors.entries_note)]),
			Api.soft_delete(Data.entries),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, BatchLifecycleTypes.Input -> Tx(EntryView.Result)
	handle = |context, input| Tx.create_many(
		Data.entries,
		[
			{ owner: context.actor(), bucket: input.bucket, rank: 1, note: "before" },
			{ owner: context.actor(), bucket: input.bucket, rank: 2, note: "before" },
		],
	).and_then(
		|created| Tx.update_many(Data.entries, created.map(|row| { row, value: { ..row.value, note: "after" } })),
	)
		.and_then(|updated| Tx.soft_delete_many(Data.entries, updated))
		.map(|retired| EntryView.summarize(retired.map(EntryView.from_row)))

	contract = {
		title: "Exercise the complete native batch lifecycle",
		usage: {
			purpose: "Create, update and soft-delete two owned rows in one native transaction.",
			use_when: ["Verifying typed batch codecs, per-row auditing and retained deletion."],
			avoid_when: ["Deleting pre-existing rows or changing another actor's rows."],
			preconditions: ["Current authority permits each row's create, note update and soft-delete."],
			effects: ["Two rows are retained at version three and six immutable mutation audits commit together."],
			result: "Two retained rows summarized after their native soft-deletion.",
		},
		inputs: { bucket: "Bucket assigned to the two new owned rows." },
		outputs: EntryView.result_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : BatchLifecycleTypes.Input, output : EntryView.Result }, Str)
	example = |_| Ok({ input: { bucket: "batch-lifecycle" }, output: { count: 2, sequence: "" } })

	verify_input : Str, U64 -> Try(BatchLifecycleTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ bucket: "batch-lifecycle-${seed.to_str()}" })

	verify_result : Str, EntryView.Result, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.verification_snapshot(before)?.live
		next = Data.verification_snapshot(after)?.live
		Ok(old.entries.len() == next.entries.len() and output.count == 2)
	}
}
