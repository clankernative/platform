import NotificationRules

SaveConfigurationTypes :: [].{
	Input := {
		app_id : Str,
		event_key : Str,
		description : Str,
		expected_revision : U64,
		version : U64,
		fields : List(NotificationRules.Field),
		template : Str,
	}

	Output : { revision : U64, version : U64 }
}
