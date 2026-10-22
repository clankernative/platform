import pf.Api
import pf.Context
import pf.Handler
import pf.Tx
import ConfigureFailureTypes
import Data
import SetupState
import Selectors

ConfigureFailure :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.create(Data.actor_states),
			Api.update(Data.actor_states, [Api.field(Selectors.actor_states_fail_second)]),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, ConfigureFailureTypes.Input -> Tx(ConfigureFailureTypes.Output)
	handle = |context, input| SetupState.configure_failure(context.actor(), input.fail_second)

	contract = {
		title: "Configure second-stage fixture failure",
		usage: {
			purpose: "Select whether this actor's second setup operation should fail.",
			use_when: ["Exercising native failure preservation in verification setup."],
			avoid_when: ["Changing an actor's preparation stage."],
			preconditions: [],
			effects: ["Changes only this actor's fail_second setting."],
			result: "The configured failure flag and current stage.",
		},
		inputs: { fail_second: "Whether second-stage preparation should reject." },
		outputs: {
			stage: "The actor's unchanged current stage.",
			fail_second: "The configured second-stage failure flag.",
		},
		example: |_| Ok({ input: { fail_second: Bool.False }, output: { stage: 0, fail_second: Bool.False } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	verify_input : Str, U64 -> Try(ConfigureFailureTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ fail_second: Bool.False })

	verify_result : Str, ConfigureFailureTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.verification_snapshot(before)?.live.actor_states
		next = Data.verification_snapshot(after)?.live.actor_states
		actor = Api.verification_context(before)?.actor
		old_stage = old.fold(
			0,
			|stage, row| if row.value.actor == actor {
				row.value.stage
			} else {
				stage
			},
		)
		Ok(
			old_stage == output.stage
				and next.any(
					|row|
						row.value.actor == actor
							and row.value.stage == output.stage
								and row.value.fail_second == output.fail_second,
				),
		)
	}
}
