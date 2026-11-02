import KeyFamilies
import Ping
import ListKeys
import InspectKey
import MetadataInvariants
import CreateClient
import CreatePersonal
import RecordUse
import RevokeClient
import RevokePersonal

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
			revoke_client: RevokeClient.definition,
			revoke_personal: RevokePersonal.definition,
			record_use: RecordUse.definition,
		},
		pages: {},
		properties: {
			entries: MetadataInvariants.entries,
			use_receipts: MetadataInvariants.use_receipts,
			key_receipts: MetadataInvariants.key_receipts,
		},
		errors: {
			invalid_client_selection: CreateClient.invalid_selection,
			invalid_personal_selection: CreatePersonal.invalid_selection,
		},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
