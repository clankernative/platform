import pf.Api
import Data

LifecycleInvariants :: [].{
	parents = Api.invariant(Data.parents, "Every live parent has an owner.", Data.snapshot, |state|
		state.parents.all(|row| !row.value.owner.is_empty()))

	children = Api.invariant(
		Data.children,
		"Every live child resolves to a live parent.",
		Data.snapshot,
		|state|
			state.children.all(
				|child| state.parents.any(|parent| parent.id == child.value.parent_id)
					and !child.value.owner.is_empty(),
			),
	)
}
