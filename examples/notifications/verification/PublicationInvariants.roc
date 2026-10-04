import pf.Api
import Data
import Publications
import NotificationRules

PublicationInvariants :: [].{
	valid =
		Api.invariant(
			Data.publications,
			"Retained publication identities and accepted snapshots are complete and immutable; only confirmed receipts claim Slack acceptance.",
			Data.snapshot,
			check,
		)

	check = |state| state.publications.len() <= 256 and state.publications.all(
		|row| {
			fields : Try(List(NotificationRules.Field), _)
			fields = Json.parse(row.value.fields_json)
			payload : Try(List(NotificationRules.Value), _)
			payload = Json.parse(row.value.payload_json)
			NotificationRules.valid_app_id(row.value.app_id) and Publications.valid_id(row.value.publication_id)
				and !row.value.actor.is_empty() and !row.value.invocation.is_empty() and row.value.accepted_at >= 0
					and state
						.definitions
						.any(
							|
								definition,
							| definition.id == row.value.definition and definition.value.app_id == row.value.app_id,
						)
						and state
							.contract_versions
							.any(
								|
									version,
								|
									version.id
										== row.value.contract_version
										and version.value.definition
											== row.value.definition
											and version.value.number <= row.value.latest_version,
							)
							and row.value.template_revision >= 1 and row.value.latest_version <= 256
								and !row.value.message.trim().is_empty()
									and NotificationRules.length(row.value.message) <= 3000
										and (if
											row.value.slack_accepted
											!row.value.channel.is_empty() and !row.value.timestamp.is_empty()
										else
											row.value.channel.is_empty() and row.value.timestamp.is_empty())
											and (match (fields, payload) {
												(Ok(schema), Ok(values)) => NotificationRules.validate_schema(schema)
													.is_empty()
													and NotificationRules.validate_payload(schema, values).is_empty()
														and Publications.valid_payload(values)
															and values == Publications.normalize(values)
												_ => Bool.False
											})
		},
	)
}
