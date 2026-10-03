import KeyFamilies
import Ping
import ListKeys
import InspectKey
import MetadataInvariants
import CreateClient
import CreatePersonal
import RecordUse
import RotateClient
import RotatePersonal
import RevokeClient
import RevokePersonal
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
			rotate_client: RotateClient.definition,
			rotate_personal: RotatePersonal.definition,
			revoke_client: RevokeClient.definition,
			revoke_personal: RevokePersonal.definition,
			record_use: RecordUse.definition,
			manage: ManageKeys.definition,
		},
		pages: { keys: Routes.keys.register() },
		properties: {
			entries: MetadataInvariants.entries,
			use_receipts: MetadataInvariants.use_receipts,
			key_receipts: MetadataInvariants.key_receipts,
		},
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "app.js" },
	}
}
