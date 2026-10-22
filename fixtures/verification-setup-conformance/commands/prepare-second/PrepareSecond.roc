import pf.Api
import pf.Context
import pf.Handler
import pf.Selection
import pf.Tx
import PrepareSecondTypes
import Data
import Commands
import Errors
import SetupState
import Selectors

PrepareSecond :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.create(Data.actor_states),
			Api.update(Data.actor_states, [Api.field(Selectors.actor_states_stage)]),
		]),
		verification: { input: verify_input, check: verify_result },
	}).verify_after(Commands.prepare_first)

	handle : Context, PrepareSecondTypes.Input -> Tx(PrepareSecondTypes.Output)
	handle = |context, _input| {
		selection = Selection.filter(Data.actor_states, Data.actor_states_actor_equal(context.actor()))
		Tx.find(selection).and_then(
			|found| match found {
				Some(row) if row.value.stage == 1 and !row.value.fail_second =>
					Tx.update(Data.actor_states, row, { ..row.value, stage: 2 })
						.map(|_| { stage: 2 })
				_ => Tx.reject(Errors.prepare_unready)
			},
		)
	}

	contract = {
		title: "Prepare actor stage two",
		usage: {
			purpose: "Complete the actor's second verification setup stage.",
			use_when: ["A checked read requires a fully prepared actor."],
			avoid_when: ["Skipping stage one or ignoring a configured failure."],
			preconditions: ["The actor is at stage one and second-stage preparation is enabled."],
			effects: ["Sets this actor's preparation stage to two."],
			result: "The resulting stage.",
		},
		inputs: {},
		outputs: { stage: "The resulting stage, always two." },
		example: |_| Ok({ input: {}, output: { stage: 2 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.prepare_unready],
	}

	verify_input : Str, U64 -> Try(PrepareSecondTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, PrepareSecondTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		states = Data.verification_snapshot(after)?.live.actor_states
		actor = Api.verification_context(before)?.actor
		Ok(output.stage == 2 and states.any(|row| row.value.actor == actor and row.value.stage == 2))
	}

	prepare_unready_error = Api.error({
		description: "Second-stage preparation requires stage one and no configured failure.",
		recovery: "Enable second-stage preparation after stage one is established.",
		verification: |_| Api.failed_command(
			Commands.prepare_second,
			|_snapshot, _seed| Ok({}),
		),
	})
}
