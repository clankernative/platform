import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import ListDealsTypes
import DealView
import Data

ListDeals :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, ListDealsTypes.Input -> Query(DealView.Page)
	handle = |_context, input|
		Query.page(Data.deals_by_stage_id(input.stage_id, input.after, input.limit))
			.map(|page| page.map(DealView.from_row))

	contract = {
		title: "List deals in a stage",
		usage: {
			purpose: "Read a bounded page using the generated relationship index.",
			use_when: ["Inspecting deals in a known stage."],
			avoid_when: ["Changing a stage."],
			preconditions: [],
			effects: [],
			result: "The page and continuation cursor.",
		},
		inputs: {
			stage_id: "The stage to inspect.",
			after: "The continuation cursor.",
			limit: "The maximum page length.",
		},
		outputs: {
			items: { description: "The matching deals.", each: DealView.fields },
			has_more: "Whether more deals are available.",
			next_after: "The continuation cursor.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : ListDealsTypes.Input, output : DealView.Page }, Str)
	example = |_| {
		deal = DealView.example({})?
		page = CollectionPage.from_parts([deal], Bool.False, Cursor.start)?
		Ok({ input: { stage_id: deal.stage_id, after: Cursor.start, limit: PageSize.default }, output: page })
	}

	verify_input : Str, U64 -> Try(ListDealsTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		stage = Data.snapshot(snapshot)?.stages.first().map_err(|_| "initialize stages first")?
		Ok({ stage_id: stage.id, after: Cursor.start, limit: PageSize.default })
	}

	verify_result : Str, DealView.Page, Str -> Try(Bool, Str)
	verify_result = |before, page, after| {
		state = Data.snapshot(before)?
		Ok(
			before == after
				and page.items().all(|view| state.deals.any(|row|
					row.id == view.id and row.version == view.version and row.value.stage_id == view.stage_id)),
		)
	}
}
