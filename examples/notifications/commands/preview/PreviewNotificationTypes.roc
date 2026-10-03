import NotificationRules
import pf.CollectionPage

PreviewNotificationTypes :: [].{
	Input := {
		app_id : Str,
		fields : List(NotificationRules.Field),
		template : Str,
		payload : List(NotificationRules.Value),
	}

	Output : { valid : Bool, message : Str, findings : CollectionPage(NotificationRules.Finding) }
}
