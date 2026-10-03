import SaveConfiguration
import GetConfiguration
import PreviewNotification
import NotificationHome
import NotificationRoutes
import ConfigurationInvariants

App :: [].{
	definition = {
		namespace: "notifications",
		operations: {
			save: SaveConfiguration.definition,
			get: GetConfiguration.definition,
			preview: PreviewNotification.definition,
			home: NotificationHome.definition,
		},
		pages: { home: NotificationRoutes.home.register() },
		properties: {
			definitions: ConfigurationInvariants.valid,
			contract_versions: ConfigurationInvariants.version_integrity,
			configuration_changes: ConfigurationInvariants.change_integrity,
		},
		errors: {
			save_denied: SaveConfiguration.save_denied,
			invalid_configuration: SaveConfiguration.invalid_configuration,
			revision_conflict: SaveConfiguration.revision_conflict,
			read_denied: GetConfiguration.read_denied,
			preview_denied: PreviewNotification.preview_denied,
		},
		examples: [],
		presentation: { stylesheet: "", script: "notifications.js" },
	}
}
