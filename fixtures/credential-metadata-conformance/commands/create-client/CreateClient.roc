import pf.Api
import pf.Handler
import pf.InteractiveContext
import pf.Credential
import pf.Tx
import CreateClientTypes
import KeyFamilies
import Credentials
import Data
import Selectors

CreateClient :: [].{
	Output : { lineage : Str, version : Str, label : Str, expires_at : I64 }

	definition = Api.command({
		handler: Handler.interactive(handle),
		contract: {
			title: "Create a named client credential",
			usage: {
				purpose: "Atomically create a client credential and its product registration.",
				use_when: ["A freshly authenticated human confirms a named client."],
				avoid_when: ["Using an ordinary app session as fresh approval."],
				preconditions: ["Exact security-origin confirmation and ready credential custody."],
				effects: ["Creates one private credential lineage and one public registration."],
				result: "Public identity and metadata, with no credential bytes.",
			},
			inputs: { label: "The exact label confirmed on the security origin." },
			outputs: {
				lineage: "Public family reference.",
				version: "Public version identity.",
				label: "Confirmed label.",
				expires_at: "Expiry in Unix seconds.",
			},
			example: |
				_,
			|
				Ok({
					input: { label: "Transcription client" },
					output: {
						lineage: "cr1_clients_example",
						version: "example",
						label: "Transcription client",
						expires_at: 3600,
					},
				}),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		execution: Api.current_state([Api.create(Data.entries), Api.create(Data.key_receipts)]),
		verification: {
			input: |_snapshot, seed| Ok({ label: "Client ${seed.to_str()}" }),
			check: |before, output, after| {
				old = Data.snapshot(before)?
				next = Data.snapshot(after)?
				Ok(
					next.entries.len()
						== old.entries.len() + 1
						and next.entries.keep_if(|row| row.value.note == output.lineage).len() == 1,
				)
			},
		},
	}).credentials(Credential.issue_access(KeyFamilies.clients)).credential_label(Selectors.create_client_input_label)

	handle : InteractiveContext, CreateClientTypes.Input -> Tx(Output)
	handle = |context, input| match Credential.Label.from_str(input.label) {
		Err(_) => Tx.succeed({ lineage: "", version: "", label: "", expires_at: 0 })
		Ok(label) => (Credentials.clients.issue)(
			context,
			{ label: label },
		).and_then(
			|issued| {
				lineage = issued.lineage().to_str()
				Tx.create(Data.entries, { note: lineage })
					.and_then(
						|
							_,
						|
							Tx.create(
								Data.key_receipts,
								{ family: "clients", lineage, head: issued.version().id(), revision: 1 },
							),
					)
					.map(
						|_| {
							{
								lineage,
								version: issued.version().id(),
								label: issued.label(),
								expires_at: issued.expires_at(),
							}
						},
					)
			},
		)
	}
}
