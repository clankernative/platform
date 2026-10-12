import pf.Ref
import pf.RowVersion
import Models

RestoreParentTypes :: [].{
	Input := { parent_id : Ref(Models.Parent), expected_version : RowVersion }
}
