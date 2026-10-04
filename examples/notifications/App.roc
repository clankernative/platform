import SaveConfiguration
import GetConfiguration
import PreviewNotification
import NotificationHome
import NotificationRoutes
import ConfigurationInvariants
import SetEnabled
import PublishNotification
import GetPublication
import PublicationInvariants
import Demo

App :: [].{
	definition = {
		namespace: "notifications",
		operations: {
			save: SaveConfiguration.definition,
			get: GetConfiguration.definition,
			preview: PreviewNotification.definition,
			set_enabled: SetEnabled.definition,
			publish: PublishNotification.definition,
			publication: GetPublication.definition,
			home: NotificationHome.definition,
		},
		pages: { home: NotificationRoutes.home.register() },
		properties: {
			definitions: ConfigurationInvariants.valid,
			contract_versions: ConfigurationInvariants.version_integrity,
			configuration_changes: ConfigurationInvariants.change_integrity,
			publications: PublicationInvariants.valid,
		},
		errors: {
			save_denied: SaveConfiguration.save_denied,
			invalid_configuration: SaveConfiguration.invalid_configuration,
			revision_conflict: SaveConfiguration.revision_conflict,
			read_denied: GetConfiguration.read_denied,
			preview_denied: PreviewNotification.preview_denied,
			publication_denied: PublishNotification.publication_denied,
			invalid_publication: PublishNotification.invalid_publication,
			publication_conflict: PublishNotification.publication_conflict,
		},
		examples: [Demo.definition],
		presentation: { stylesheet: "", script: "notifications.js" },
	}
}
