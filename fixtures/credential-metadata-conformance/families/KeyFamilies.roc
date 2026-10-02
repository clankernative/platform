import pf.Credential
import pf.Api
import Reads
import Commands

KeyFamilies :: [].{
	clients =
		Credential.client_family({
			id: "client_keys",
			grant: Credential.fixed([Api.read(Reads.ping), Api.write(Commands.record_use)]),
			lifetime_seconds: 3600,
		})

	personal =
		Credential.personal_family({
			id: "personal_keys",
			grant: Credential.fixed([Api.read(Reads.ping), Api.write(Commands.record_use)]),
			lifetime_seconds: 3600,
		})
}
