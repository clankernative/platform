import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.RowVersion
import pf.Selection
import pf.Cursor
import pf.PageSize
import RemoveChildTypes
import LifecycleView
import Data
import Selectors

RemoveChild :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.edit(
			Data.children,
			Selectors.remove_child_input_child_id,
			Selectors.remove_child_input_expected_version,
			[Api.soft_delete(Data.children)],
		),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, RemoveChildTypes.Input -> Tx(LifecycleView.ChildSaved)
	handle = |_context, input| {
		observed = if input.attempt_other {
			Tx.page(Selection.including_deleted(Data.all_children(Cursor.start, PageSize.maximum))).and_then(
				|page| match page.items().find_first(|candidate| candidate.id != input.child_id) {
					Ok(other) => Tx.succeed(other)
					Err(_) => Tx.get(Data.children, input.child_id)
				},
			)
		} else {
			Tx.find(
				Selection.including_deleted(Selection.filter(Data.children, Data.children_id_equal(input.child_id))),
			)
				.and_then(
					|found| match found {
						Some(row) => Tx.succeed(row)
						None => Tx.get(Data.children, input.child_id)
					},
				)
		}
		observed
			.and_then(|row| Tx.soft_delete(Data.children, row).map(|saved| { id: saved.id, version: saved.version }))
	}

	contract = {
		title: "Remove a child",
		usage: {
			purpose: "Hide a record without removing its values.",
			use_when: ["Exercising deletion."],
			avoid_when: [],
			preconditions: ["Supply the observed identifier and revision."],
			effects: ["Changes lifecycle state and advances the concurrency revision."],
			result: "The same identifier with the committed revision.",
		},
		inputs: {
			child_id: "The target record.",
			expected_version: "The observed revision.",
			attempt_other: "Conformance probe: request an effect on another owned row; the host must refuse.",
		},
		outputs: LifecycleView.saved_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : RemoveChildTypes.Input, output : LifecycleView.ChildSaved }, Str)
	example = |_| {
		id = LifecycleView.child_id({})?
		version = RowVersion.from_u64(1).map_err(|_| "invalid example version")?
		next = RowVersion.from_u64(2).map_err(|_| "invalid example version")?
		Ok({
			input: { child_id: id, expected_version: version, attempt_other: Bool.False },
			output: { id, version: next },
		})
	}

	verify_input : Str, U64 -> Try(RemoveChildTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row = Data.verification_snapshot(snapshot)?.live.children.first().map_err(|_| "create a live child first")?
		Ok({ child_id: row.id, expected_version: row.version, attempt_other: Bool.False })
	}

	verify_result : Str, LifecycleView.ChildSaved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old =
			Data.verification_snapshot(before)?
				.live
				.children
				.find_first(|candidate| candidate.id == saved.id)
				.map_err(|_| "missing original target")?
		state = Data.verification_snapshot(after)?
		row =
			state
				.deleted
				.children
				.find_first(|candidate| candidate.id == saved.id)
				.map_err(|_| "missing changed target")?
		Ok(
			row.version == saved.version and row.version.to_u64() == old.version.to_u64() + 1
				and row.value.owner == old.value.owner and row.value.title.to_str() == old.value.title.to_str()
					and row.value.parent_id == old.value.parent_id
						and !state.live.children.any(|other| other.id == saved.id),
		)
	}
}
