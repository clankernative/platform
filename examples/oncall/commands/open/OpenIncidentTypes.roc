import pf.Ref
import pf.RowVersion
import Models

OpenIncidentTypes :: [].{
	Input := { title : Str }
	Saved : { id : Ref(Models.Incident), version : RowVersion }
}
