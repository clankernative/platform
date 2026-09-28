import pf.Ref
import Models

EscalateIncidentTypes :: [].{
	Input := { incident_id : Ref(Models.Incident) }
	Result : { escalated : Bool, rung : I64, reason : Str }
}
