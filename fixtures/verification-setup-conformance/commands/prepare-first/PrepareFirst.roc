import pf.Api
import pf.Context
import pf.Handler
import pf.Tx
import PrepareFirstTypes
import Data
import SetupState
import Selectors

PrepareFirst :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.create(Data.actor_states),
			Api.update(Data.actor_states, [Api.field(Selectors.actor_states_stage)]),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, PrepareFirstTypes.Input -> Tx(PrepareFirstTypes.Output)
	handle = |context, _input| SetupState.prepare_first(context.actor()).map(|_| { stage: 1 })

	contract = {
		title: "Prepare actor stage one",
		usage: {
			purpose: "Advance an actor to the first verification setup stage.",
			use_when: ["A checked follow-up requires stage one."],
			avoid_when: ["Changing another actor's state."],
			preconditions: [],
			effects: ["Sets this actor's preparation stage to one."],
			result: "The resulting stage.",
		},
		inputs: {},
		outputs: { stage: "The resulting stage, always one." },
		example: |_| Ok({ input: {}, output: { stage: 1 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	verify_input : Str, U64 -> Try(PrepareFirstTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, PrepareFirstTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.verification_snapshot(before)?.live.actor_states
		next = Data.verification_snapshot(after)?.live.actor_states
		actor = Api.verification_context(before)?.actor
		old_failure = old.fold(
			Bool.False,
			|failure, row|
				if row.value.actor == actor {
					row.value.fail_second
				} else {
					failure
				},
		)
		Ok(
			output.stage == 1
				and next.any(
					|row|
						row.value.actor == actor
							and row.value.stage == 1
								and row.value.fail_second == old_failure,
				),
		)
	}
}
