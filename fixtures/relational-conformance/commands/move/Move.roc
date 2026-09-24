import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import MoveTypes
import DealView
import Data
import Selectors
import Commands
import Errors
import pf.RowVersion

Move :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.update(Data.deals, [Api.field(Selectors.deals_stage_id)]),
			Api.update(Data.stages, [Api.field(Selectors.stages_deal_count)]),
			Api.create(Data.history),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, MoveTypes.Input -> Tx(DealView.Saved)
	handle = |context, input| Tx.get(Data.deals, input.deal_id).and_then(
		|deal|
			if deal.version != input.expected_version {
				Tx.reject(Errors.stale_revision)
			} else if deal.value.stage_id == input.target_stage_id {
				Tx.succeed({ id: deal.id, version: deal.version })
			} else {
				Tx.get(Data.stages, deal.value.stage_id).and_then(
					|source|
						Tx.get(Data.stages, input.target_stage_id).and_then(
							|target|
								Tx.update(
									Data.stages,
									source,
									{ ..source.value, deal_count: source.value.deal_count - 1 },
								)
									.and_then(
										|_|
											Tx.update(
												Data.stages,
												target,
												{ ..target.value, deal_count: target.value.deal_count + 1 },
											)
												.and_then(
													|_|
														Tx.update(
															Data.deals,
															deal,
															{ ..deal.value, stage_id: target.id },
														)
															.and_then(
																|saved|
																	Tx.create(
																		Data.history,
																		{
																			deal_id: deal.id,
																			from_stage_id: source.id,
																			to_stage_id: target.id,
																			occurred_at: context.now(),
																		},
																	).map(|_| { id: saved.id, version: saved.version }),
															),
												),
									),
						),
				)
			},
	)

	contract = {
		title: "Move a deal",
		usage: {
			purpose: "Move a deal between stages atomically.",
			use_when: ["Changing the current stage."],
			avoid_when: ["Initializing the database."],
			preconditions: ["Read the current deal revision."],
			effects: ["Updates both stage counts and the deal; appends history."],
			result: "The deal identifier and committed revision.",
		},
		inputs: {
			deal_id: "The deal to move.",
			target_stage_id: "The destination stage.",
			expected_version: "The revision read before moving.",
		},
		outputs: DealView.saved_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.stale_revision],
	}

	example : {} -> Try({ input : MoveTypes.Input, output : DealView.Saved }, Str)
	example = |_| {
		deal = DealView.example({})?
		Ok({
			input: { deal_id: deal.id, target_stage_id: deal.stage_id, expected_version: deal.version },
			output: { id: deal.id, version: deal.version },
		})
	}

	verify_input : Str, U64 -> Try(MoveTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		state = Data.snapshot(snapshot)?
		deal = state.deals.first().map_err(|_| "initialize a deal first")?
		target = state.stages.find_first(|stage| stage.id != deal.value.stage_id).map_err(|_| "missing other stage")?
		Ok({ deal_id: deal.id, target_stage_id: target.id, expected_version: deal.version })
	}

	verify_result : Str, DealView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		deal = old.deals.find_first(|row| row.id == saved.id).map_err(|_| "missing previous deal")?
		row = next.deals.find_first(|item| item.id == saved.id).map_err(|_| "missing moved deal")?
		Ok(
			row.version == saved.version
				and row.version.to_u64() == deal.version.to_u64() + 1
					and row.value.stage_id != deal.value.stage_id
						and next.history.len() == old.history.len() + 1,
		)
	}

	stale_revision = Api.error({
		description: "The deal changed after its revision was read.",
		recovery: "Read the deal again and retry with the current revision.",
		verification: |_| Api.failed_command(Commands.move, stale_input),
	})

	stale_input : Str, U64 -> Try(MoveTypes.Input, Str)
	stale_input = |snapshot, seed| {
		input = verify_input(snapshot, seed)?
		expected_version = RowVersion.from_u64(input.expected_version.to_u64() + 1).map_err(|_| "revision exhausted")?
		Ok({ ..input, expected_version })
	}

}
