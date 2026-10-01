import pf.Api
import pf.Handler
import pf.Query
import pf.Context
import pf.SecurityAction
import SecurityActions
import ProductReturns
import ManageKeysTypes
import CreateClientTypes
import CreatePersonalTypes

ManageKeys :: [].{
	Navigation : { operation : Str, payload : Str, product_return : Str }

	Output : { client : Navigation, personal : Navigation }

	definition = Api.query({
		handler: Handler.local(handle),
		contract: {
			title: "Manage credential keys",
			usage: {
				purpose: "Bind product commands to protected credential navigation.",
				use_when: ["Creating a client or personal key."],
				avoid_when: [],
				preconditions: [],
				effects: [],
				result: "Safe navigation data for the exact typed product inputs.",
			},
			inputs: {},
			outputs: {
				client: {
					description: "Client creation navigation.",
					fields: {
						operation: "Canonical product command.",
						payload: "Canonical input JSON.",
						product_return: "Admitted app page.",
					},
				},
				personal: {
					description: "Personal creation navigation.",
					fields: {
						operation: "Canonical product command.",
						payload: "Canonical input JSON.",
						product_return: "Admitted app page.",
					},
				},
			},
			example: |_| Ok({ input: {}, output: navigation({}) }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({}),
			check: |before, output, after| Ok(
				before == after
					and output.client.operation == "credential_metadata.create_client"
						and output.personal.operation == "credential_metadata.create_personal"
							and output.client.product_return == "keys" and output.personal.product_return == "keys",
			),
		},
	})

	navigation : {} -> Output
	navigation = |_| {
		client_input : CreateClientTypes.Input
		client_input = { label: "Transcription client" }
		personal_input : CreatePersonalTypes.Input
		personal_input = { label: "Personal key" }
		{
			client: SecurityAction.bind(SecurityActions.create_client, client_input, ProductReturns.keys),
			personal: SecurityAction.bind(SecurityActions.create_personal, personal_input, ProductReturns.keys),
		}
	}

	handle : Context, ManageKeysTypes.Input -> Query(Output)
	handle = |_context, _input| Query.from_try(Ok(navigation({})))
}
