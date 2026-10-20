import pf.Api
import pf.Context
import pf.Handler
import pf.Query
import pf.Selection
import BReadTypes
import Data
import Reads
import Commands
import Errors

BRead :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	}).verify_after(Commands.prepare_first).verify_after(Commands.prepare_second)

	handle : Context, BReadTypes.Input -> Query(BReadTypes.Output)
	handle = |context, _input| {
		selection = Selection.filter(Data.actor_states, Data.actor_states_actor_equal(context.actor()))
		Query.find(selection).and_then(
			|found| match found {
				Some(row) if row.value.stage == 2 => Query.from_try(Ok({ stage: row.value.stage }))
				_ => Query.from_try(Err(Errors.read_unprepared))
			},
		)
	}

	contract = {
		title: "Read a fully prepared actor",
		usage: {
			purpose: "Observe an actor's state after both registered setup operations.",
			use_when: ["A caller needs a checked stage-two result."],
			avoid_when: ["Reading an actor before preparation."],
			preconditions: ["The actor is at stage two."],
			effects: [],
			result: "The actor's prepared stage.",
		},
		inputs: {},
		outputs: { stage: "The prepared stage, always two." },
		example: |_| Ok({ input: {}, output: { stage: 2 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.read_unprepared],
	}

	verify_input : Str, U64 -> Try(BReadTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, BReadTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		states = Data.verification_snapshot(before)?.live.actor_states
		actor = Api.verification_context(before)?.actor
		Ok(
			before == after
				and output.stage == 2
					and states.any(|row| row.value.actor == actor and row.value.stage == 2),
		)
	}

	read_unprepared = Api.error({
		description: "The actor has not completed both preparation stages.",
		recovery: "Run the registered preparation commands before reading.",
		verification: |_| Api.failed_query_as(
			Reads.b_read,
			Api.verification_principal("setup-unprepared-query"),
			|_snapshot, _seed| Ok({}),
		),
	})
}
