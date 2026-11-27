import pf.Api
import pf.Context
import pf.Handler
import pf.Tx
import Data
import Commands
import Errors
import IntakePolicy
import ConfigureTypes

Configure :: [].{
	definition =
		Api.command({
			audience: Owners,
			handler: Handler.local(handle),
			contract,
			execution: Api.current_state([Api.create(Data.settings)]),
			verification: { input: |_, _| Ok(IntakePolicy.example({})), check: verify_result },
		})
			.require_all_rows(Data.settings)

	handle : Context, ConfigureTypes.Input -> Tx(ConfigureTypes.Output)
	handle = |ctx, input| {
		if !IntakePolicy.direct(ctx) or !IntakePolicy.valid(input) {
			return Tx.reject(Errors.invalid_settings)
		}
		Tx.find(IntakePolicy.selection({})).and_then(
			|found| match found {
				None => Tx.create(
					Data.settings,
					{
						install_key: 1,
						product_owners: input.product_owners,
						reviewer: input.reviewer,
						contract_folder: input.contract_folder,
					},
				)
					.map(|_| { configured: Bool.True })
				Some(row) => if
					row.value.product_owners
						== input.product_owners
						and row.value.reviewer == input.reviewer and row.value.contract_folder == input.contract_folder
						{
							Tx.succeed({ configured: Bool.True })
						}
							else
								{
									Tx.reject(Errors.frozen_settings)
								}
			},
		)
	}

	contract =
		{
			title: "Configure the vendor intake installation",
			usage: {
				purpose: "Bind the authorized requester group, sole reviewer and contract folder once.",
				use_when: ["An app owner installs this verified artifact."],
				avoid_when: [],
				preconditions: ["A directly authenticated owner and valid immutable settings."],
				effects: ["Creates one immutable settings row or confirms identical settings."],
				result: "Configuration is active.",
			},
			inputs: {
				product_owners: "Primary Google group email for requesters.",
				reviewer: "Sole authenticated reviewer email.",
				contract_folder: "Canonical HTTPS Google Drive folder URL.",
			},
			outputs: { configured: "True when those settings are active." },
			example: |_| Ok({ input: IntakePolicy.example({}), output: { configured: Bool.True } }),
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
			errors: [Errors.invalid_settings, Errors.frozen_settings],
		}

	verify_result : Str, ConfigureTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, out, after| {
		old = Data.verification_snapshot(before)?
		new = Data.verification_snapshot(after)?
		decoded : Try({ product_owners : Str, reviewer : Str, contract_folder : Str }, _)
		decoded = Json.parse(Api.verification_context(before)?.input)
		input = decoded.map_err(|_| "invalid settings input")?
		row = new.live.settings.first().map_err(|_| "configuration missing")?
		Ok(
			out.configured
				and new.live.settings.len()
					== 1
					and new.deleted.settings.is_empty()
						and row.value.install_key
							== 1
							and row.version.to_u64()
								== 1
								and row.value.product_owners
									== input.product_owners
									and row.value.reviewer
										== input.reviewer
										and row.value.contract_folder
											== input.contract_folder
											and old
												.live
												.settings
												.all(
													|
														prior,
													|
														prior.id
															== row.id
															and prior.value == row.value,
												),
		)
	}

	invalid_settings = Api.error({
		description: "A direct owner must supply canonical group, reviewer and folder settings.",
		recovery: "Check both email addresses and the canonical Drive folder URL.",
		verification: |_| Api.failed_command(
			Commands.configure,
			|_, _| {
				base = IntakePolicy.example({})
				Ok({ ..base, reviewer: "" })
			},
		),
	})

	frozen_settings = Api.error({
		description: "This installation has already been configured differently.",
		recovery: "Inspect this installation or provision a separately reviewed installation.",
		verification: |_| Api.failed_command(
			Commands.configure,
			|_, _| {
				base = IntakePolicy.example({})
				Ok({ ..base, reviewer: "another@synthetic.example" })
			},
		),
	})
}
