import pf.Credential
import pf.Api
import Reads

KeyFamilies :: [].{
	clients =
		Credential.client_family(
			{ id: "client_keys", grant: Credential.fixed([Api.read(Reads.ping)]), lifetime_seconds: 3600 },
		)

	personal =
		Credential.personal_family(
			{ id: "personal_keys", grant: Credential.fixed([Api.read(Reads.ping)]), lifetime_seconds: 3600 },
		)
}
