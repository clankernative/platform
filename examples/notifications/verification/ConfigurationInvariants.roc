import pf.Api
import NotificationRules
import Data

ConfigurationInvariants :: [].{
	valid = Api.invariant(
		Data.definitions,
		"Configurations have valid schemas, contiguous versions and an immutable change for every revision.",
		Data.snapshot,
		check,
	)

	version_integrity =
		Api.invariant(
			Data.contract_versions,
			"Every contract version belongs to a valid configuration.",
			Data.snapshot,
			check,
		)

	change_integrity =
		Api.invariant(
			Data.configuration_changes,
			"Every configuration revision has an immutable actor-attributed change.",
			Data.snapshot,
			check,
		)

	check = |state| state.definitions.all(
		|definition| {
			versions = state.contract_versions.keep_if(|row| row.value.definition == definition.id)
			changes = state.configuration_changes.keep_if(|row| row.value.definition == definition.id)
			NotificationRules.valid_app_id(definition.value.app_id)
				and !versions.is_empty() and versions.len() <= 256
					and changes.len() == definition.value.revision
						and changes.all(
							|row| !row.value.actor.is_empty() and row.value.revision >= 1
								and row.value.revision <= definition.value.revision
									and changes.keep_if(|other| other.value.revision == row.value.revision).len()
										== 1,
						)
							and versions.all(
								|row| {
									fields : Try(List(NotificationRules.Field), _)
									fields = Json.parse(row.value.fields_json)
									match fields {
										Err(_) => Bool.False
										Ok(schema) => NotificationRules.validate_configuration(
											definition.value.event_key,
											definition.value.description,
											schema,
											row.value.template,
										)
											.is_empty()
											and row.value.fields_json == Json.to_str(schema)
												and row.value.number >= 1 and row.value.number <= versions.len()
													and versions
														.keep_if(|other| other.value.number == row.value.number)
														.len()
														== 1
														and row.value.template_revision
															>= 1
															and row.value.template_revision
																<= definition.value.revision
									}
								},
							)
		},
	)
}
