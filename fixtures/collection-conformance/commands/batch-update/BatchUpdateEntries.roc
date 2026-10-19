import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.Selection
import pf.Predicate
import pf.Ref
import pf.RowVersion
import pf.Failure
import Models
import Errors
import BatchUpdateEntriesTypes
import EntryView
import Data
import Selectors
import Commands

BatchUpdateEntries :: [].{
	CheckedChange : { id : Ref(Models.Entry), version : RowVersion, note : Str }

	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.update(Data.entries, [Api.field(Selectors.entries_note)])]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, BatchUpdateEntriesTypes.Input -> Tx(EntryView.Result)
	handle = |_context, input| match input.changes.map_try(decode_change) {
		Err(error) => Tx.reject(error)
		Ok([]) => Tx.succeed(EntryView.summarize([]))
		Ok(changes) => update_changes(changes)
	}

	decode_change : BatchUpdateEntriesTypes.Change -> Try(CheckedChange, Failure)
	decode_change = |change| {
		version = RowVersion.from_u64(change.version).map_err(|_| Errors.batch_update_version_invalid)?
		id = Ref.for_model("ent", change.id).map_err(|_| Errors.batch_update_missing)?
		Ok({ id, version, note: change.note })
	}

	update_changes : List(CheckedChange) -> Tx(EntryView.Result)
	update_changes = |changes| Tx.collect(
		Selection.filter(Data.entries, Predicate.any(changes.map(|change| Data.entries_id_equal(change.id)))),
		256,
	).and_then(
		|rows| {
			updates = changes.map_try(
				|change| match rows.find_first(|candidate| candidate.id == change.id) {
					Err(_) => Err(Errors.batch_update_missing)
					Ok(current) => Ok(
						{ row: { ..current, version: change.version }, value: { ..current.value, note: change.note } },
					)
				},
			)
			match updates {
				Err(error) => Tx.reject(error)
				Ok(batch) => Tx.update_many(Data.entries, batch)
					.map(|saved| EntryView.summarize(saved.map(EntryView.from_row)))
			}
		},
	)

	contract = {
		title: "Update a bounded collection atomically",
		usage: {
			purpose: "Exercise one homogeneous typed update batch with per-row observed revisions.",
			use_when: ["Updating a complete set of visible entries atomically."],
			avoid_when: ["Committing a partial set or ignoring a stale row."],
			preconditions: ["Every listed row is visible and its version is current."],
			effects: ["All notes update together or no row changes; batch is bounded to 256 rows."],
			result: "The updated entries in submitted order.",
		},
		inputs: {
			changes: {
				description: "Bounded ordered rows to update atomically.",
				each: {
					id: "Checked entry reference text.",
					version: "Positive observed row version.",
					note: "Replacement note.",
				},
			},
		},
		outputs: EntryView.result_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.batch_update_missing, Errors.batch_update_version_invalid],
	}

	missing = Api.error({
		description: "A requested entry reference is invalid, missing or not visible.",
		recovery: "Refresh the complete collection and retry with current rows.",
		verification: |_| Api.failed_command(Commands.batch_update, missing_input),
	})

	invalid_version = Api.error({
		description: "An expected row revision is outside the positive SQLite revision range.",
		recovery: "Reload the current row revisions.",
		verification: |_| Api.failed_command(Commands.batch_update, invalid_version_input),
	})

	invalid_version_input : Str, U64 -> Try(BatchUpdateEntriesTypes.Input, Str)
	invalid_version_input = |snapshot, seed| {
		input = missing_input(snapshot, seed)?
		Ok({ changes: input.changes.map(|change| { ..change, version: 0 }) })
	}

	example : {} -> Try({ input : BatchUpdateEntriesTypes.Input, output : EntryView.Result }, Str)
	example = |_| {
		row = EntryView.sample({})?
		Ok({
			input: { changes: [{ id: row.id.to_str(), version: row.version.to_u64(), note: "after" }] },
			output: EntryView.summarize([{ ..row, note: "after" }]),
		})
	}

	missing_input : Str, U64 -> Try(BatchUpdateEntriesTypes.Input, Str)
	missing_input = |_snapshot, _seed| {
		row = EntryView.sample({})?
		Ok({ changes: [{ id: row.id.to_str(), version: row.version.to_u64(), note: "after" }] })
	}

	verify_input : Str, U64 -> Try(BatchUpdateEntriesTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row = Data.verification_snapshot(snapshot)?.live.entries.first().map_err(|_| "insert an entry first")?
		Ok({ changes: [{ id: row.id.to_str(), version: row.version.to_u64(), note: "after" }] })
	}

	verify_result : Str, EntryView.Result, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.verification_snapshot(before)?.live
		next = Data.verification_snapshot(after)?.live
		Ok(old.entries.len() == next.entries.len() and output.count <= next.entries.len())
	}
}
