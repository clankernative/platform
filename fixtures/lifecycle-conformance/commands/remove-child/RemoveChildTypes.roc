import pf.Ref
import pf.RowVersion
import Models

RemoveChildTypes :: [].{
	Input := { child_id : Ref(Models.Child), expected_version : RowVersion, attempt_other : Bool }
}
