import pf.Ref
import pf.RowVersion
import Models

RestoreChildTypes :: [].{
	Input := { child_id : Ref(Models.Child), expected_version : RowVersion, attempt_other : Bool }
}
