import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Tx
import pf.Model
import Models
import Data
import Selectors
import Commands
import Errors
import NotificationAccess
import NotificationRules
import Configurations
import SaveConfigurationTypes

SaveConfiguration :: [].{
	definition = Api.command({
		handler: Handler.prepared(prepare, handle),
		contract,
		execution: Api.current_state([
			Api.create(Data.definitions),
			Api.update(
				Data.definitions,
				[Api.field(Selectors.definitions_description), Api.field(Selectors.definitions_revision)],
			),
			Api.create(Data.contract_versions),
			Api.update(
				Data.contract_versions,
				[
					Api.field(Selectors.contract_versions_template),
					Api.field(Selectors.contract_versions_template_revision),
				],
			),
			Api.create(Data.configuration_changes),
		]),
		verification: { input: verify_input, check: verify_result },
	}).require_all_rows(Data.definitions).require_all_rows(Data.contract_versions)

	prepare : Context, SaveConfigurationTypes.Input -> Observe(Bool)
	prepare = |_context, input| NotificationAccess.check(input.app_id)

	handle : Context, SaveConfigurationTypes.Input, Bool -> Tx(SaveConfigurationTypes.Output)
	handle = |context, input, allowed| {
		if !allowed {
			return Tx.reject(Errors.save_denied)
		}
		if
			!NotificationRules.validate_configuration(input.event_key, input.description, input.fields, input.template)
				.is_empty()
				{
					return Tx.reject(Errors.invalid_configuration)
				}
		Tx.find(Configurations.definition(input.app_id, input.event_key)).and_then(
			|found| {
				current_revision = match found {
					None => 0
					Some(row) => row.value.revision
				}
				if input.expected_revision != current_revision or current_revision >= 1_000_000 {
					return Tx.reject(Errors.revision_conflict)
				}
				revision = current_revision + 1
				enabled = match found {
					None => Bool.False
					Some(row) => row.value.enabled
				}
				value =
					{
						app_id: input.app_id,
						event_key: input.event_key,
						description: input.description,
						revision,
						enabled,
					}
				write = match found {
					None => Tx.create(Data.definitions, value)
					Some(row) => Tx.update(Data.definitions, row, value)
				}
				write.and_then(
					|definition_row| save_version(input, definition_row, revision).and_then(
						|number| {
							Tx.create(
								Data.configuration_changes,
								{ definition: definition_row.id, revision, actor: context.actor() },
							)
								.map(|_| { revision, version: number })
						},
					),
				)
			},
		)
	}

	save_version : SaveConfigurationTypes.Input, Model.Entity(Models.Definition), U64 -> Tx(U64)
	save_version = |input, definition_row, revision| {
		fields_json = Json.to_str(input.fields)
		if input.version == 0 {
			Tx.collect(Configurations.versions(definition_row.id), 256).and_then(
				|versions| {
					if versions.len() >= 256 {
						return Tx.reject(Errors.invalid_configuration)
					}
					number =
						versions.fold(0, |maximum, row| if row.value.number > maximum row.value.number else maximum) + 1
					Tx.create(
						Data.contract_versions,
						{
							definition: definition_row.id,
							number,
							fields_json,
							template: input.template,
							template_revision: revision,
						},
					)
						.map(|_| number)
				},
			)
		} else {
			Tx.find(Configurations.version(definition_row.id, input.version)).and_then(
				|found| match found {
					None => Tx.reject(Errors.invalid_configuration)
					Some(row) => {
						if row.value.fields_json != fields_json {
							return Tx.reject(Errors.invalid_configuration)
						}
						Tx.update(
							Data.contract_versions,
							row,
							{ ..row.value, template: input.template, template_revision: revision },
						)
							.map(|_| input.version)
					}
				},
			)
		}
	}

	contract = {
		title: "Save a notification configuration",
		usage: {
			purpose: "Create a contract version or edit its template after checking current app ownership.",
			use_when: ["An app owner configures event messages."],
			avoid_when: ["Changing delivery enablement or an existing version's field schema."],
			preconditions: [
				"Current direct app ownership, the current revision and a serialized schema within 16 KiB.",
			],
			effects: ["Atomically saves the definition, version and immutable actor-attributed change record."],
			result: "The committed definition revision and contract version. Existing delivery enablement is preserved.",
		},
		inputs: {
			app_id: "Business app identifier.",
			event_key: "Event name.",
			description: "Nonblank event description, up to 500 UTF-16 units.",
			expected_revision: "Current revision; zero creates a definition.",
			version: "Zero creates a version; a positive number edits its template.",
			fields: NotificationRules.field_input,
			template: "Text with declared {{field}} placeholders, up to 3000 UTF-16 units.",
		},
		outputs: { revision: "Committed configuration revision.", version: "Saved contract version." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.save_denied, Errors.invalid_configuration, Errors.revision_conflict],
	}

	example : {} -> Try({ input : SaveConfigurationTypes.Input, output : SaveConfigurationTypes.Output }, Str)
	example = |_| Ok({ input: sample(0), output: { revision: 1, version: 1 } })

	sample : U64 -> SaveConfigurationTypes.Input
	sample =
		|
			revision,
		|
			{
				app_id: "demo",
				event_key: "build.completed",
				description: "A build completed.",
				expected_revision: revision,
				version: 0,
				fields: NotificationRules.summary_fields,
				template: "Build: {{summary}}",

			}

	verify_input : Str, U64 -> Try(SaveConfigurationTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		state = Data.snapshot(snapshot)?
		revision =
			match state
				.definitions
				.find_first(|row| row.value.app_id == "demo" and row.value.event_key == "build.completed") {
				Err(_) => 0
				Ok(row) => row.value.revision
			}
		Ok(sample(revision))
	}

	verify_result : Str, SaveConfigurationTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.configuration_changes.len() == old.configuration_changes.len() + 1
				and next.contract_versions.len() == old.contract_versions.len() + 1
					and next
						.definitions
						.any(
							|
								row,
							|
								row.value.app_id
									== "demo"
									and row.value.event_key
										== "build.completed"
										and row.value.revision == output.revision,
						),
		)
	}

	save_denied =
		Api.error_cases({
			description: "Current ownership did not authorize this save or enablement change.",
			recovery: "Ask an ownership administrator for access.",
			verification: |_| [
				Api.failed_command(Commands.save, |_snapshot, _seed| Ok({ ..sample(0), app_id: "" })),
				Api.failed_command(
					Commands.set_enabled,
					|
						_snapshot,
						_seed,
					| Ok({ app_id: "", event_key: "build.completed", expected_revision: 0, enabled: Bool.False }),
				),
			],
		})

	invalid_configuration =
		Api.error_cases({
			description: "Configuration is invalid, its stored schema exceeds 16 KiB, the version is missing or changed, or its bound is exhausted.",
			recovery: "Correct or reduce the schema, or create a new contract version without changing an existing schema.",
			verification: |_| [
				Api.failed_command(Commands.save, |_snapshot, _seed| Ok({ ..sample(0), template: "{{missing}}" })),
				Api.failed_command(
					Commands.set_enabled,
					|
						_snapshot,
						_seed,
					| Ok({ app_id: "demo", event_key: "missing.event", expected_revision: 0, enabled: Bool.False }),
				),
			],
		})

	revision_conflict =
		Api.error_cases({
			description: "The edit's expected revision is stale or the revision bound is exhausted.",
			recovery: "Read the current configuration and review the edit again.",
			verification: |_| [
				Api.failed_command(Commands.save, |_snapshot, _seed| Ok(sample(1_000_001))),
				Api.failed_command(
					Commands.set_enabled,
					|
						_snapshot,
						_seed,
					|
						Ok({
							app_id: "demo",
							event_key: "build.completed",
							expected_revision: 1_000_001,
							enabled: Bool.False,
						}),
				),
			],
		})
}
