import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Query
import pf.CollectionPage
import Data
import Reads
import Errors
import Configurations
import NotificationAccess
import NotificationRules
import GetConfigurationTypes

GetConfiguration :: [].{
	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		}).require_all_rows(Data.definitions).require_all_rows(Data.contract_versions)

	prepare : Context, GetConfigurationTypes.Input -> Observe(Bool)
	prepare = |_context, input| NotificationAccess.check(input.app_id)

	handle : Context, GetConfigurationTypes.Input, Bool -> Query(GetConfigurationTypes.Output)
	handle = |_context, input, allowed| {
		if !allowed {
			return Query.from_try(Err(Errors.read_denied))
		}
		Query.find(Configurations.definition(input.app_id, input.event_key)).and_then(
			|found| match found {
				None => Query.succeed(missing(input))
				Some(definition_row) => Query.collect(Configurations.versions(definition_row.id), 256).and_then(
					|versions| {
						number =
							if
								input.version != 0
								input.version
							else
								versions
									.fold(0, |maximum, row| if row.value.number > maximum row.value.number else maximum)
						match versions.find_first(|row| row.value.number == number) {
							Err(_) => Query.succeed(missing(input))
							Ok(row) => {
								fields : Try(List(NotificationRules.Field), _)
								fields = Json.parse(row.value.fields_json)
								match fields {
									Err(_) => Query.from_try(Err(Errors.read_denied))
									Ok(schema) => if
										!NotificationRules.validate_configuration(
											input.event_key,
											definition_row.value.description,
											schema,
											row.value.template,
										)
											.is_empty()
											{
												Query.from_try(Err(Errors.read_denied))
											}
												else
													{
														Query.succeed({
															found: Bool.True,
															app_id: input.app_id,
															event_key: input.event_key,
															description: definition_row.value.description,
															revision: definition_row.value.revision,
															version: number,
															fields: CollectionPage.complete(
																schema
																	.map(
																		|
																			field,
																		|
																			{
																				name: field.name,
																				kind: field.kind,
																				max_length: field.max_length,
																				choices: CollectionPage.complete(
																					field.choices,
																				),
																			},
																	),
															),
															template: row.value.template,
															template_revision: row.value.template_revision,
															enabled: Bool.False,
														})
													}
								}
							}
						}
					},
				)
			},
		)
	}

	missing : GetConfigurationTypes.Input -> GetConfigurationTypes.Output
	missing =
		|
			input,
		|
			{
				found: Bool.False,
				app_id: input.app_id,
				event_key: input.event_key,
				description: "",
				revision: 0,
				version: 0,
				fields: CollectionPage.empty,
				template: "",
				template_revision: 0,
				enabled: Bool.False,

			}

	contract = {
		title: "Read a notification configuration",
		usage: {
			purpose: "Read a version only after checking current app ownership.",
			use_when: ["Reviewing or editing event configuration."],
			avoid_when: ["Treating an old ownership decision as current permission."],
			preconditions: ["Current direct app ownership."],
			effects: [],
			result: "The requested version, or found=false; delivery stays disabled.",
		},
		inputs: {
			app_id: "Business app identifier.",
			event_key: "Event name.",
			version: "Zero selects the latest contract version.",
		},
		outputs: {
			found: "Whether the requested version exists.",
			app_id: "Business app identifier.",
			event_key: "Event name.",
			description: "Event description.",
			revision: "Current configuration revision.",
			version: "Contract version.",
			fields: {
				description: "Complete immutable field schema for this version.",
				fields: {
					items: {
						description: "All fields, at most 20.",
						each: {
							name: "Field name.",
							kind: "text, integer, boolean or enum.",
							max_length: "Maximum text length in UTF-16 units.",
							choices: {
								description: "Complete enum choices.",
								fields: {
									items: { description: "All choices, at most 50.", each: "Enum choice." },
									has_more: "Always false.",
									next_after: "Empty; this is complete.",
								},
							},
						},
					},
					has_more: "Always false.",
					next_after: "Empty; this is complete.",
				},
			},
			template: "Current version template.",
			template_revision: "Revision that last changed this template.",
			enabled: "False until delivery support is implemented.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.read_denied],
	}

	example : {} -> Try({ input : GetConfigurationTypes.Input, output : GetConfigurationTypes.Output }, Str)
	example = |_| {
		input : GetConfigurationTypes.Input
		input = { app_id: "demo", event_key: "build.completed", version: 0 }
		Ok({ input, output: missing(input) })
	}

	verify_input : Str, U64 -> Try(GetConfigurationTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ app_id: "demo", event_key: "build.completed", version: 0 })

	verify_result : Str, GetConfigurationTypes.Output, Str -> Try(Bool, Str)
	verify_result =
		|
			before,
			output,
			after,
		| Ok(before == after and !output.enabled and (!output.found or output.revision >= output.template_revision))

	read_denied =
		Api.error({
			description: "Current ownership or stored configuration integrity did not authorize this read.",
			recovery: "Ask an ownership administrator for access; an operator can inspect configuration integrity.",
			verification: |
				_,
			|
				Api.failed_query(
					Reads.get,
					|_snapshot, _seed| Ok({ app_id: "", event_key: "build.completed", version: 0 }),
				),
		})
}
