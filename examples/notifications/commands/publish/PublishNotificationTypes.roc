import NotificationRules

PublishNotificationTypes :: [].{
	Input := {
		app_id : Str,
		event_key : Str,
		version : U64,
		publication_id : Str,
		payload : List(NotificationRules.Value),
	}
}
