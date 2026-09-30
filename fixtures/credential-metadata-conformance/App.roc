import KeyFamilies
import Ping
import ListKeys
import InspectKey
import MetadataInvariants

App :: [].{
	definition = {
		namespace: "credential_metadata",
		credentials: { clients: KeyFamilies.clients, personal: KeyFamilies.personal },
		operations: { ping: Ping.definition, list: ListKeys.definition, inspect: InspectKey.definition },
		pages: {},
		properties: { entries: MetadataInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
