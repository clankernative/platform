import KeyFamilies
import Ping
import ListKeys
import InspectKey
import MetadataInvariants
import CreateClient
import CreatePersonal
import ManageKeys
import Routes

App :: [].{
	definition = {
		namespace: "credential_metadata",
		credentials: { clients: KeyFamilies.clients, personal: KeyFamilies.personal },
		operations: {
			ping: Ping.definition,
			list: ListKeys.definition,
			inspect: InspectKey.definition,
			create_client: CreateClient.definition,
			create_personal: CreatePersonal.definition,
			manage: ManageKeys.definition,
		},
		pages: { keys: Routes.keys.register() },
		properties: { entries: MetadataInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "app.js" },
	}
}
