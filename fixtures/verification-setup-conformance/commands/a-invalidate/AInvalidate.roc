import pf.Api
import pf.Context
import pf.Handler
import pf.Tx
import AInvalidateTypes
import Data
import Commands
import SetupState
import Selectors

AInvalidate :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.create(Data.actor_states),
			Api.update(
				Data.actor_states,
				[
					Api.field(Selectors.actor_states_stage),
					Api.field(Selectors.actor_states_fail_second),
				],
			),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, AInvalidateTypes.Input -> Tx(AInvalidateTypes.Output)
	handle = |context, _input| {
		actor = context.actor()
		SetupState.invalidate(actor).map(|_| { stage: 0 })
	}

	contract = {
		title: "Invalidate actor preparation",
		usage: {
			purpose: "Reset one actor's setup state before verification reads it.",
			use_when: ["Testing that registered verification setup is actually required."],
			avoid_when: ["Production account state."],
			preconditions: [],
			effects: ["Sets this actor's preparation stage to zero without changing its failure setting."],
			result: "The reset stage.",
		},
		inputs: {},
		outputs: { stage: "The resulting stage, always zero." },
		example: |_| Ok({ input: {}, output: { stage: 0 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	verify_input : Str, U64 -> Try(AInvalidateTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, AInvalidateTypes.Output, Str -> Try(Bool, Str)
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
			output.stage == 0
				and next.any(
					|row|
						row.value.actor == actor
							and row.value.stage == 0
								and row.value.fail_second == old_failure,
				),
		)
	}
}
