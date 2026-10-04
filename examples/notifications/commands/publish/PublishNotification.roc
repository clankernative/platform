import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Tx
import pf.Effects
import pf.Resource
import pf.Slack
import pf.Model
import pf.Cursor
import pf.PageSize
import Models
import Data
import Selectors
import Commands
import Reads
import Errors
import NotificationRules
import NotificationAccess
import Configurations
import Publications
import PublishNotificationTypes

PublishNotification :: [].{
	Facts : { allowed : Bool, resource : [Some(Resource), None] }

	Decision : { row : Model.Entity(Models.Publication), resource : Resource, dispatch : Bool }

	definition = Api.command({
		handler: Handler.effects(prepare, decide, deliver, complete),
		contract,
		execution: Api.current_state([
			Api.create(Data.publications),
			Api.update_created(
				Data.publications,
				[
					Api.field(Selectors.publications_slack_accepted),
					Api.field(Selectors.publications_channel),
					Api.field(Selectors.publications_timestamp),
				],
			),
			Slack.post_effect,
		]),
		verification: { input: verify_input, check: verify_result },
	}).require_all_rows(Data.definitions).require_all_rows(Data.contract_versions).require_all_rows(Data.publications)

	prepare : Context, PublishNotificationTypes.Input -> Observe(Facts)
	prepare = |context, input| NotificationAccess.check(input.app_id).and_then(
		|allowed| {
			if allowed {
				Resource.bind(context, "notification_channel").map(|resource| { allowed, resource: Some(resource) })
			} else {
				Observe.value({ allowed, resource: None })
			}
		},
	)

	decide : Context, PublishNotificationTypes.Input, Facts -> Tx(Decision)
	decide = |context, input, facts| {
		if !facts.allowed {
			return Tx.reject(Errors.publication_denied)
		}
		resource = match facts.resource {
			Some(bound) => bound
			None => return Tx.reject(Errors.publication_denied)
		}
		if !Publications.valid_id(input.publication_id) or !NotificationRules.valid_event_key(input.event_key)
			or input.version == 0 or !Publications.valid_payload(input.payload) {
			return Tx.reject(Errors.invalid_publication)
		}
		# Retained identity is checked before current enablement/version/template.
		Tx.find(Publications.find(input.app_id, input.publication_id)).and_then(
			|existing| match existing {
				Some(row) => Tx.get(Data.definitions, row.value.definition).and_then(
					|definition_row| {
						Tx.get(Data.contract_versions, row.value.contract_version).and_then(
							|version_row| {
								if
									definition_row.value.event_key
										!= input.event_key
										or version_row.value.number != input.version
											or !Publications.same_payload(row.value.payload_json, input.payload)
										{
											Tx.reject(Errors.publication_conflict)
										}
											else
												{
													Tx.succeed({ row, resource, dispatch: Bool.False })
												}
							},
						)
					},
				)
				None => Tx.find(Configurations.definition(input.app_id, input.event_key)).and_then(
					|found| match found {
						None => Tx.reject(Errors.invalid_publication)
						Some(definition_row) => {
							if !definition_row.value.enabled {
								return Tx.reject(Errors.invalid_publication)
							}
							Tx.find(Configurations.version(definition_row.id, input.version)).and_then(
								|version| match version {
									None => Tx.reject(Errors.invalid_publication)
									Some(version_row) => accept(context, input, resource, definition_row, version_row)
								},
							)
						}
					},
				)
			},
		)
	}

	accept :
		Context,
		PublishNotificationTypes.Input,
		Resource,
		Model.Entity(Models.Definition),
		Model.Entity(Models.ContractVersion) ->
			Tx(Decision)
	accept = |context, input, resource, definition_row, version_row| {
		fields : Try(List(NotificationRules.Field), _)
		fields = Json.parse(version_row.value.fields_json)
		match fields {
			Err(_) => Tx.reject(Errors.invalid_publication)
			Ok(schema) => {
				rendered = NotificationRules.render(schema, version_row.value.template, input.payload)
				if
					!rendered.valid
						or rendered.message.trim().is_empty()
							or rendered.message.to_utf8().any(|byte| byte < 32 and byte != 9 and byte != 10)
						{
							return Tx.reject(Errors.invalid_publication)
						}
				Tx.collect(Data.all_publications(Cursor.start, PageSize.maximum), 256).and_then(
					|publications| {
						if publications.len() >= 256 {
							return Tx.reject(Errors.invalid_publication)
						}
						Tx.collect(Configurations.versions(definition_row.id), 256).and_then(
							|versions| {
								latest =
									versions
										.fold(
											0,
											|maximum, row| if row.value.number > maximum row.value.number else maximum,
										)
								Tx.create(
									Data.publications,
									{
										app_id: input.app_id,
										publication_id: input.publication_id,
										definition: definition_row.id,
										contract_version: version_row.id,
										latest_version: latest,
										template_revision: version_row.value.template_revision,
										fields_json: version_row.value.fields_json,
										payload_json: Json.to_str(Publications.normalize(input.payload)),
										message: rendered.message,
										actor: context.actor(),
										invocation: context.invocation_id(),
										accepted_at: context.now(),
										slack_accepted: Bool.False,
										channel: "",
										timestamp: "",
									},
								).map(|row| { row, resource, dispatch: Bool.True })
							},
						)
					},
				)
			}
		}
	}

	deliver : Decision -> Effects(Slack.Receipt)
	deliver = |decision| if decision.dispatch {
		Slack.post(decision.resource, decision.row.value.message)
	} else {
		Effects.value({ channel: "", timestamp: "", status: "skipped" })
	}

	complete : Context, PublishNotificationTypes.Input, Decision, Slack.Receipt -> Tx(Publications.Output)
	complete = |_context, _input, decision, receipt| if !decision.dispatch {
		Tx.succeed(Publications.output(decision.row, Bool.True))
	} else if receipt.status == "accepted" and !receipt.channel.is_empty() and !receipt.timestamp.is_empty() {
		Tx.get(Data.publications, decision.row.id).and_then(
			|row| {
				Tx.update(
					Data.publications,
					row,
					{ ..row.value, slack_accepted: Bool.True, channel: receipt.channel, timestamp: receipt.timestamp },
				)
					.map(|updated| Publications.output(updated, Bool.False))
			},
		)
	} else {
		Tx.reject(Errors.invalid_publication)
	}

	contract = {
		title: "Publish and deliver a notification",
		usage: {
			purpose: "Accept an explicit event version and post its captured message to the operator-bound Slack channel.",
			use_when: ["An app owner publishes an event under inherited human authority."],
			avoid_when: [
				"Machine-origin ingress, selecting recipients, or retrying an uncertain message with a new identity.",
			],
			preconditions: [
				"Current ownership and channel grant; a new publication requires an enabled event and valid explicit version.",
			],
			effects: [
				"Commits an immutable publication snapshot before provider I/O, then records validated Slack acceptance in completion.",
			],
			result: "Slack acceptance or an original retained publication. Consult the original command status for refusal, blocking or uncertainty; unconfirmed never means unsent.",
		},
		inputs: {
			app_id: "Business app identifier.",
			event_key: "Configured event.",
			version: "Explicit positive contract version.",
			publication_id: "Stable business identity, up to 128 UTF-16 units; reuse unchanged on retry.",
			payload: NotificationRules.value_input,
		},
		outputs: Publications.output_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.publication_denied, Errors.invalid_publication, Errors.publication_conflict],
	}

	sample : PublishNotificationTypes.Input
	sample =
		{
			app_id: "demo",
			event_key: "build.completed",
			version: 1,
			publication_id: "build-1",
			payload: [{ name: "summary", kind: "text", text: "passed", integer: 0, boolean: Bool.False }],

		}

	example : {} -> Try({ input : PublishNotificationTypes.Input, output : Publications.Output }, Str)
	example = |_| Ok({ input: sample, output: Publications.example({})? })

	verify_input : Str, U64 -> Try(PublishNotificationTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ ..sample, publication_id: "build-${seed.to_str()}" })

	verify_result : Str, Publications.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		row =
			next
				.publications
				.find_first(|candidate| candidate.id == output.notification_id)
				.map_err(|_| "publication missing")?
		Ok(output.slack_accepted and row.value.slack_accepted and next.publications.len() == old.publications.len() + 1)
	}

	publication_denied =
		Api.error_cases({
			description: "Current ownership did not authorize publication or disclosure.",
			recovery: "Ask an ownership administrator for access.",
			verification: |_| [
				Api.failed_command(Commands.publish, |_snapshot, _seed| Ok({ ..sample, app_id: "" })),
				Api.failed_query(Reads.publication, |_snapshot, _seed| Ok({ app_id: "", publication_id: "build-1" })),
			],
		})

	invalid_publication =
		Api.error_cases({
			description: "The event is disabled, unknown or invalid; version, payload, message or retained capacity is invalid.",
			recovery: "Review enablement and the explicit event contract. Do not resend uncertain accepted work under another identity.",
			verification: |_| [
				Api.failed_command(Commands.publish, |_snapshot, _seed| Ok({ ..sample, version: 0 })),
				Api.failed_query(
					Reads.publication,
					|_snapshot, _seed| Ok({ app_id: "demo", publication_id: "missing-publication" }),
				),
			],
		})

	publication_conflict = Api.error({
		description: "This publication identity already names different business input.",
		recovery: "Reuse the original input for the existing identity.",
		verification: |_| Api.failed_command(
			Commands.publish,
			|snapshot, _seed| {
				row = Data.snapshot(snapshot)?.publications.first().map_err(|_| "publish an event first")?
				payload : List(NotificationRules.Value)
				payload = Json.parse(row.value.payload_json).map_err(|_| "invalid retained payload")?
				Ok({
					..sample,
					app_id: row.value.app_id,
					publication_id: row.value.publication_id,
					event_key: "conflicting.event",
					payload,
				})
			},
		),
	})
}
