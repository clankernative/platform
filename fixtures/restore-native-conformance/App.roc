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
import RestoreCalendarConnection
import RestoreMarkers

App :: [].{
	definition = {
		namespace: "oauthcalendar",
		connections: { calendar: RestoreCalendarConnection.requirement },
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
			restore_markers: RestoreMarkers.definition,
		},
		pages: {},
		properties: {
			entries: MetadataInvariants.entries,
			use_receipts: MetadataInvariants.use_receipts,
			key_receipts: MetadataInvariants.key_receipts,
		},
		errors: {
			client_refused: CreateClient.refused,
			personal_refused: CreatePersonal.refused,
		},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
