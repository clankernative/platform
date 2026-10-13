import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.RowVersion
import pf.Selection
import RemoveParentTypes
import LifecycleView
import Data
import Selectors

RemoveParent :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.edit(
			Data.parents,
			Selectors.remove_parent_input_parent_id,
			Selectors.remove_parent_input_expected_version,
			[Api.soft_delete(Data.parents)],
		),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, RemoveParentTypes.Input -> Tx(LifecycleView.ParentSaved)
	handle =
		|
			_context,
			input,
		|
			Tx.find(
				Selection.including_deleted(Selection.filter(Data.parents, Data.parents_id_equal(input.parent_id))),
			)
				.and_then(
					|found| match found {
						Some(row) => Tx.soft_delete(Data.parents, row)
							.map(|saved| { id: saved.id, version: saved.version })
						None => Tx.get(Data.parents, input.parent_id).and_then(|row|
							Tx.soft_delete(Data.parents, row).map(|saved| { id: saved.id, version: saved.version }))
					},
				)

	contract = {
		title: "Remove a parent",
		usage: {
			purpose: "Hide a record without removing its values.",
			use_when: ["Exercising deletion."],
			avoid_when: [],
			preconditions: ["Supply the observed identifier and revision."],
			effects: ["Changes lifecycle state and advances the concurrency revision."],
			result: "The same identifier with the committed revision.",
		},
		inputs: { parent_id: "The target record.", expected_version: "The observed revision." },
		outputs: LifecycleView.saved_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : RemoveParentTypes.Input, output : LifecycleView.ParentSaved }, Str)
	example = |_| {
		id = LifecycleView.parent_id({})?
		version = RowVersion.from_u64(1).map_err(|_| "invalid example version")?
		next = RowVersion.from_u64(2).map_err(|_| "invalid example version")?
		Ok({ input: { parent_id: id, expected_version: version }, output: { id, version: next } })
	}

	verify_input : Str, U64 -> Try(RemoveParentTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row =
			Data.verification_snapshot(snapshot)?
				.live
				.parents
				.find_first(|candidate| candidate.value.title.to_str() == "Spare")
				.map_err(|_| "create a live parent first")?
		Ok({ parent_id: row.id, expected_version: row.version })
	}

	verify_result : Str, LifecycleView.ParentSaved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old =
			Data.verification_snapshot(before)?
				.live
				.parents
				.find_first(|candidate| candidate.id == saved.id)
				.map_err(|_| "missing original target")?
		state = Data.verification_snapshot(after)?
		row =
			state
				.deleted
				.parents
				.find_first(|candidate| candidate.id == saved.id)
				.map_err(|_| "missing changed target")?
		Ok(
			row.version == saved.version and row.version.to_u64() == old.version.to_u64() + 1
				and row.value.owner == old.value.owner and row.value.title.to_str() == old.value.title.to_str()
					and !state.live.parents.any(|other| other.id == saved.id),
		)
	}
}
