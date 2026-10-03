import pf.Observe
import ImportedContracts
import NotificationRules

NotificationAccess :: [].{
	check : Str -> Observe(Bool)
	check = |app_id| if NotificationRules.valid_app_id(app_id) {
		ImportedContracts.app_ownership_check({ app_id: app_id })
			.map(|decision| decision.app_id == app_id and decision.allowed)
	} else {
		Observe.value(Bool.False)
	}
}
