import pf.Ref
import pf.Text
import Title
import Models

CreateLifecycleTypes :: [].{
	Input := {
		parent_id : Ref(Models.Parent),
		reuse_parent : Bool,
		parent_title : Text(Title),
		spare_title : Text(Title),
		child_title : Text(Title),
	}
}
