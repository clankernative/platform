import pf.Ref
import pf.RowVersion
import Models

LifecycleView :: [].{
	ParentSaved : { id : Ref(Models.Parent), version : RowVersion }

	ChildSaved : { id : Ref(Models.Child), version : RowVersion }

	Created : { parent_id : Ref(Models.Parent), spare_parent_id : Ref(Models.Parent), child_id : Ref(Models.Child) }

	saved_fields = { id: "The stable record identifier.", version: "The committed concurrency revision." }

	created_fields = {
		parent_id: "The referenced parent.",
		spare_parent_id: "The parent with no children.",
		child_id: "The child referencing the first parent.",
	}

	parent_id : {} -> Try(Ref(Models.Parent), Str)
	parent_id = |_| Ref.from_str("par_0000000000e008000000000000").map_err(|_| "invalid parent example")

	child_id : {} -> Try(Ref(Models.Child), Str)
	child_id = |_| Ref.from_str("chi_0000000000e008000000000000").map_err(|_| "invalid child example")

	spare_parent_id : {} -> Try(Ref(Models.Parent), Str)
	spare_parent_id = |_| Ref.from_str("par_0000000000e008000000000001").map_err(|_| "invalid spare example")
}
