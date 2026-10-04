import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Tx
import pf.Resource
import Data
import Selectors
import Errors
import Configurations
import NotificationAccess
import SetEnabledTypes

SetEnabled :: [].{
	definition = Api.command({
		handler: Handler.prepared(prepare, handle),
		contract,
		execution: Api.current_state([
			Api.update(
				Data.definitions,
				[Api.field(Selectors.definitions_revision), Api.field(Selectors.definitions_enabled)],
			),
			Api.create(Data.configuration_changes),
		]),
		verification: { input: verify_input, check: verify_result },
	}).require_all_rows(Data.definitions)

	prepare : Context, SetEnabledTypes.Input -> Observe(Bool)
	prepare = |context, input| NotificationAccess.check(input.app_id).and_then(
		|allowed| {
			if allowed and input.enabled {
				# Binding proves current operator authority, not live channel readiness.
				Resource.bind(context, "notification_channel").map(|_| Bool.True)
			} else {
				Observe.value(allowed)
			}
		},
	)

	handle : Context, SetEnabledTypes.Input, Bool -> Tx(SetEnabledTypes.Output)
	handle = |context, input, allowed| {
		if !allowed {
			return Tx.reject(Errors.save_denied)
		}
		Tx.find(Configurations.definition(input.app_id, input.event_key)).and_then(
			|found| match found {
				None => Tx.reject(Errors.invalid_configuration)
				Some(row) => {
					if row.value.revision != input.expected_revision or row.value.revision >= 1_000_000 {
						return Tx.reject(Errors.revision_conflict)
					}
					revision = row.value.revision + 1
					Tx.update(Data.definitions, row, { ..row.value, revision, enabled: input.enabled }).and_then(
						|updated| {
							Tx.create(
								Data.configuration_changes,
								{ definition: updated.id, revision, actor: context.actor() },
							)
								.map(|_| { revision, enabled: input.enabled })
						},
					)
				}
			},
		)
	}

	contract = {
		title: "Enable or disable notification publication",
		usage: {
			purpose: "Change acceptance of new publications after checking ownership and the operator-bound channel grant.",
			use_when: ["An owner enables a configured event or stops new publications."],
			avoid_when: ["Cancelling an already accepted delivery or selecting another channel."],
			preconditions: ["Current ownership and configuration revision; enabling also requires the channel grant."],
			effects: ["Updates enablement and records an actor-attributed configuration revision."],
			result: "The new revision and enablement. Binding does not certify live Slack readiness.",
		},
		inputs: {
			app_id: "Business app identifier.",
			event_key: "Configured event.",
			expected_revision: "Current revision.",
			enabled: "Accept new publications.",
		},
		outputs: { revision: "Committed revision.", enabled: "New enablement." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.save_denied, Errors.invalid_configuration, Errors.revision_conflict],
	}

	example : {} -> Try({ input : SetEnabledTypes.Input, output : SetEnabledTypes.Output }, Str)
	example =
		|
			_,
		|
			Ok({
				input: { app_id: "demo", event_key: "build.completed", expected_revision: 1, enabled: Bool.True },
				output: { revision: 2, enabled: Bool.True },
			})

	verify_input : Str, U64 -> Try(SetEnabledTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row = Data.snapshot(snapshot)?.definitions.first().map_err(|_| "configure an event first")?
		Ok({
			app_id: row.value.app_id,
			event_key: row.value.event_key,
			expected_revision: row.value.revision,
			enabled: Bool.True,
		})
	}

	verify_result : Str, SetEnabledTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.definitions.len()
				== old.definitions.len()
				and next.configuration_changes.len() == old.configuration_changes.len() + 1 and output.enabled,
		)
	}
}
