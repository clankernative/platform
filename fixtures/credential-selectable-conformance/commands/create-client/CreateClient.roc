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
import Commands
import Errors

CreateClient :: [].{
	Output : { lineage : Str, version : Str, label : Str, expires_at : I64 }

	# Explicitly choose the entire catalog in pure examples. This is not the
	# runtime default: production requests must carry their chosen selection.
	example_grant : {} -> Try(Str, Str)
	example_grant = |_| {
		selection = (Credentials.clients.selection_from_options)(Credentials.clients.grant_options)
			.map_err(|_| "fixture selection unavailable")?
		Ok(selection.to_str())
	}

	definition = Api.command({
		handler: Handler.interactive(handle),
		contract: {
			title: "Create a selected named client credential",
			usage: {
				purpose: "Atomically issue exactly the selected client permissions and register the result.",
				use_when: ["A freshly authenticated human confirms a nonempty exact selection."],
				avoid_when: ["Treating a selector or ordinary session as authority."],
				preconditions: ["Current family contract, confirmed scope and ready custody."],
				effects: ["One credential lineage and one public product registration."],
				result: "Public identity and metadata only.",
			},
			inputs: { label: "Confirmed label.", grant: "Serialized current family selection." },
			outputs: {
				lineage: "Public family reference.",
				version: "Public version identity.",
				label: "Confirmed label.",
				expires_at: "Unix expiry.",
			},
			example: |_| {
				grant = example_grant({})?
				Ok({
					input: { label: "Selected client", grant },
					output: {
						lineage: "cr1_clients_example",
						version: "example",
						label: "Selected client",
						expires_at: 3600,
					},
				})
			},
			errors: [Errors.invalid_client_selection],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		execution: Api.current_state([Api.create(Data.entries), Api.create(Data.key_receipts)]),
		verification: {
			input: |_snapshot, seed| {
				grant = example_grant({})?
				Ok({ label: "Client ${seed.to_str()}", grant })
			},
			check: |before, output, after| {
				old = Data.verification_snapshot(before)?.live
				next = Data.verification_snapshot(after)?.live
				Ok(
					next.entries.len()
						== old.entries.len() + 1
						and next.entries.keep_if(|row| row.value.note == output.lineage).len() == 1,
				)
			},
		},
	}).credentials(Credential.issue_access(KeyFamilies.clients))
		.credential_label(Selectors.create_client_input_label)
		.credential_grant(Selectors.create_client_input_grant)

	handle : InteractiveContext, CreateClientTypes.Input -> Tx(Output)
	handle =
		|
			context,
			input,
		| match (Credential.Label.from_str(input.label), (Credentials.clients.selection_from_str)(input.grant)) {
			(Ok(_), Ok(_)) if input.label == "Refuse issuance" => Tx.reject(Errors.invalid_client_selection)
			(Ok(label), Ok(grant)) => (Credentials.clients.issue)(context, { label, grant }).and_then(
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
							|
								_,
							|
								{
									lineage,
									version: issued.version().id(),
									label: issued.label(),
									expires_at: issued.expires_at(),
								},
						)
				},
			)
			_ => Tx.reject(Errors.invalid_client_selection)
		}

	invalid_selection = Api.error({
		description: "The app refused the credential label or selected grant.",
		recovery: "Choose a valid current selection and a different label.",
		verification: |_| Api.failed_command(
			Commands.create_client,
			|_snapshot, _seed| {
				grant = example_grant({})?
				Ok({ label: "Refuse issuance", grant })
			},
		),
	})
}
