import pf.Api
import Data

RelationalInvariants :: [].{
	relationships = Api.invariant(
		Data.deals,
		"Every deal and history reference resolves.",
		Data.snapshot,
		|state|
			state.deals.all(|deal| state.stages.any(|stage| stage.id == deal.value.stage_id))
				and state.history.all(
					|entry|
						state.deals.any(|deal| deal.id == entry.value.deal_id)
							and state.stages.any(|stage| stage.id == entry.value.from_stage_id)
								and state.stages.any(|stage| stage.id == entry.value.to_stage_id),
				),
	)

	counts = Api.invariant(
		Data.stages,
		"Stage counts equal their related deals.",
		Data.snapshot,
		|state|
			state.stages.all(
				|stage|
					stage.value.deal_count >= 0
						and stage.value.deal_count.to_u64_try()
							== Ok(state.deals.keep_if(|deal| deal.value.stage_id == stage.id).len()),
			),
	)

	history = Api.invariant(
		Data.history,
		"Each deal revision after creation has one history entry.",
		Data.snapshot,
		|state|
			state.history.all(|entry| state.deals.any(|deal| deal.id == entry.value.deal_id))
				and state.deals.all(
					|deal|
						deal.version.to_u64()
							== state.history.keep_if(|entry| entry.value.deal_id == deal.id).len() + 1,
				),
	)
}
