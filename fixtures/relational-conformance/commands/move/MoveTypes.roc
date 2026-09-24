import pf.Ref
import pf.RowVersion
import Models

MoveTypes :: [].{
	Input := { deal_id : Ref(Models.Deal), target_stage_id : Ref(Models.Stage), expected_version : RowVersion }
}
