import KeyFamilies
import Ping
import ListKeys
import InspectKey
import MetadataInvariants
import CreateClient
import CreatePersonal

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
		},
		pages: {},
		properties: { entries: MetadataInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
