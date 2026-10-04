import pf.CollectionPage

GetConfigurationTypes :: [].{
	Input := { app_id : Str, event_key : Str, version : U64 }

	Output : {
		found : Bool,
		app_id : Str,
		event_key : Str,
		description : Str,
		revision : U64,
		version : U64,
		fields : CollectionPage({ name : Str, kind : Str, max_length : U64, choices : CollectionPage(Str) }),
		template : Str,
		template_revision : U64,
		enabled : Bool,
	}
}
