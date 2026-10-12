import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import CreateLifecycleTypes
import LifecycleView
import Data
import Domains

CreateLifecycle :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.parents), Api.create(Data.children)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, CreateLifecycleTypes.Input -> Tx(LifecycleView.Created)
	handle = |context, input| Tx.create(Data.parents, { title: input.parent_title, owner: context.actor() }).and_then(
		|parent| Tx.create(Data.parents, { title: input.spare_title, owner: context.actor() }).and_then(
			|spare| Tx.create(
				Data.children,
				{
					title: input.child_title,
					parent_id: if input.reuse_parent {
						input.parent_id
					} else {
						parent.id
					},
					owner: context.actor(),
				},
			).map(
				|child| {
					parent_id: if input.reuse_parent {
						input.parent_id
					} else {
						parent.id
					},
					spare_parent_id: spare.id,
					child_id: child.id,
				},
			),
		),
	)

	contract = {
		title: "Create lifecycle records",
		usage: {
			purpose: "Create a referenced parent, a spare parent and a child in one transaction.",
			use_when: ["Starting a lifecycle scenario."],
			avoid_when: [],
			preconditions: [],
			effects: ["Creates two parents and one child owned by the actor."],
			result: "The three stable identifiers.",
		},
		inputs: {
			parent_id: "An existing parent used only by the relationship probe.",
			parent_title: "The referenced parent title.",
			spare_title: "The spare parent title.",
			child_title: "The child title.",
			reuse_parent: "Conformance probe: attach the child to the supplied parent.",
		},
		outputs: LifecycleView.created_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : CreateLifecycleTypes.Input, output : LifecycleView.Created }, Str)
	example = |_| Ok({
		input: {
			parent_id: LifecycleView.parent_id({})?,
			reuse_parent: Bool.False,
			parent_title: Domains.title("Referenced parent")?,
			spare_title: Domains.title("Spare")?,
			child_title: Domains.title("Child")?,
		},
		output: {
			parent_id: LifecycleView.parent_id({})?,
			spare_parent_id: LifecycleView.spare_parent_id({})?,
			child_id: LifecycleView.child_id({})?,
		},
	})

	verify_input : Str, U64 -> Try(CreateLifecycleTypes.Input, Str)
	verify_input =
		|
			_snapshot,
			_seed,
		|
			Ok({
				parent_id: LifecycleView.parent_id({})?,
				reuse_parent: Bool.False,
				parent_title: Domains.title("Referenced parent")?,
				spare_title: Domains.title("Spare")?,
				child_title: Domains.title("Child")?,
			})

	verify_result : Str, LifecycleView.Created, Str -> Try(Bool, Str)
	verify_result = |before, created, after| {
		old = Data.verification_snapshot(before)?.live
		next = Data.verification_snapshot(after)?.live
		Ok(
			next.parents.len() == old.parents.len() + 2
				and next.children.len() == old.children.len() + 1
					and next.parents.any(|row| row.id == created.parent_id)
						and next.parents.any(|row| row.id == created.spare_parent_id)
							and next
								.children
								.any(|row| row.id == created.child_id and row.value.parent_id == created.parent_id),
		)
	}
}
