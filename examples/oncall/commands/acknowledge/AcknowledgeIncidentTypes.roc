import pf.Ref
import pf.RowVersion
import Models

AcknowledgeIncidentTypes :: [].{
	Input := { incident_id : Ref(Models.Incident), expected_version : RowVersion }
	Saved : { id : Ref(Models.Incident), version : RowVersion }
}
