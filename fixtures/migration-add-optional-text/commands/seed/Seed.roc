import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.Cursor
import pf.PageSize
import pf.Ref
import SeedTypes
import DealView
import Data
import Domains
import Commands
import Errors

Seed :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.stages), Api.create(Data.deals)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, SeedTypes.Input -> Tx(DealView.Seeded)
	handle = |_context, input| Tx.page(Data.all_stages(Cursor.start, PageSize.one)).and_then(
		|existing|
			if !existing.items().is_empty() {
				Tx.page(Data.all_deals(Cursor.start, PageSize.one)).and_then(
					|deals|
						match deals.items().first() {
							Err(_) => Tx.reject(Errors.already_initialized)
							Ok(deal) => if deal.value.title.to_str() != input.title.to_str() {
								Tx.reject(Errors.already_initialized)
							} else {
								Tx.page(Data.all_stages(Cursor.start, PageSize.default)).and_then(
									|stages|
										match stages.items().find_first(|stage| stage.id != deal.value.stage_id) {
											Err(_) => Tx.reject(Errors.already_initialized)
											Ok(target) => Tx.succeed({
												deal_id: deal.id,
												source_stage_id: deal.value.stage_id,
												target_stage_id: target.id,
											})
										},
								)
							}
						},
				)
			} else {
				Tx.create(Data.stages, { name: "Qualified", deal_count: 1 }).and_then(|source|
					Tx.create(Data.stages, { name: "Won", deal_count: 0 }).and_then(|target|
						Tx.create(Data.deals, { title: input.title, stage_id: source.id, note: None }).map(|deal|
							{ deal_id: deal.id, source_stage_id: source.id, target_stage_id: target.id })))
			},
	)

	contract = {
		title: "Initialize relational conformance",
		usage: {
			purpose: "Create two stages and one related deal.",
			use_when: ["Starting an empty conformance database."],
			avoid_when: ["Replacing an initialized database with a different title."],
			preconditions: ["The database is empty or contains the same titled deal."],
			effects: ["Creates two stages and one deal in one transaction."],
			result: "The created or previously initialized identifiers.",
		},
		inputs: { title: "The initial deal title." },
		outputs: DealView.seeded_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.already_initialized],
	}

	example : {} -> Try({ input : SeedTypes.Input, output : DealView.Seeded }, Str)
	example = |_| {
		deal = DealView.example({})?
		target = Ref.from_str("sta_0000000000e008000000000001").map_err(|_| "invalid target example")?
		Ok({
			input: { title: deal.title },
			output: { deal_id: deal.id, source_stage_id: deal.stage_id, target_stage_id: target },
		})
	}

	verify_input : Str, U64 -> Try(SeedTypes.Input, Str)
	verify_input = |snapshot, seed| match Data.snapshot(snapshot)?.deals.first() {
		Ok(deal) => Ok({ title: deal.value.title })
		Err(_) => Ok({ title: Domains.title("Generated deal ${seed.to_str()}")? })
	}

	verify_result : Str, DealView.Seeded, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			(old.stages.is_empty() or before == after)
				and next.stages.len() == 2
					and next.deals.len() == 1
						and next
							.deals
							.any(|deal| deal.id == saved.deal_id and deal.value.stage_id == saved.source_stage_id)
							and next
								.stages
								.any(|stage| stage.id == saved.target_stage_id and stage.value.deal_count == 0),
		)
	}

	rejected_input : Str, U64 -> Try(SeedTypes.Input, Str)
	rejected_input = |snapshot, _seed| {
		deal = Data.snapshot(snapshot)?.deals.first().map_err(|_| "initialize a deal first")?
		title = Domains.title(
			if deal.value.title.to_str() == "Different title" {
				"Another title"
			} else {
				"Different title"
			},
		)?
		Ok(
			{ title: title },
		)
	}

	already_initialized = Api.error({
		description: "The conformance database is initialized with a different title.",
		recovery: "Use a new database for initialization.",
		verification: |_| Api.failed_command(Commands.seed, rejected_input),
	})
}
