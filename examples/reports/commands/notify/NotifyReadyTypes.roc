import pf.Ref
import pf.RowVersion
import Models

NotifyReadyTypes :: [].{
	Input := { report_id : Ref(Models.Report), expected_version : RowVersion }
}
