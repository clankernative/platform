import CreateLifecycle
import RemoveParent
import RemoveChild
import RestoreParent
import RestoreChild
import LifecycleInvariants

App :: [].{
	definition = {
		namespace: "lifecycle",
		operations: {
			create: CreateLifecycle.definition,
			remove_child: RemoveChild.definition,
			remove_parent: RemoveParent.definition,
			restore_child: RestoreChild.definition,
			restore_parent: RestoreParent.definition,
		},
		properties: { parents: LifecycleInvariants.parents, children: LifecycleInvariants.children },
		pages: {},
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
