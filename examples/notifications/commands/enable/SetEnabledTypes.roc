SetEnabledTypes :: [].{
	Input := { app_id : Str, event_key : Str, expected_revision : U64, enabled : Bool }

	Output : { revision : U64, enabled : Bool }
}
