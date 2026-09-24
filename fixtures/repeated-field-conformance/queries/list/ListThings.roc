import pf.Handler
import pf.Api
import pf.Query
import pf.Context
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import ListThingsTypes
import ThingView
import Data

ListThings :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, ListThingsTypes.Input -> Query(ThingView.Page)
	handle = |_context, input| Query.page(Data.all_things(input.after, input.limit))
		.map(|page| page.map(ThingView.from_row))

	contract = {
		title: "List things",
		usage: {
			purpose: "Browse stored rows and their decoded tags in a bounded page.",
			use_when: ["Checking how repeated form controls decoded."],
			avoid_when: ["Anything other than conformance testing."],
			preconditions: [],
			effects: [],
			result: "A page of rows with tag counts and joined tags.",
		},
		inputs: { after: "Continuation cursor; empty starts the list.", limit: "The maximum page length." },
		outputs: {
			items: { description: "Stored rows.", each: ThingView.fields },
			has_more: "Whether another page is available.",
			next_after: "The next continuation cursor.",
		},
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : ListThingsTypes.Input, output : ThingView.Page }, Str)
	example = |_| {
		row = ThingView.sample_view({})?
		page = CollectionPage.from_parts([row], Bool.False, Cursor.start)?
		Ok({ input: { after: Cursor.start, limit: PageSize.default }, output: page })
	}

	verify_input : Str, U64 -> Try(ListThingsTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ after: Cursor.start, limit: PageSize.default })

	verify_result : Str, ThingView.Page, Str -> Try(Bool, Str)
	verify_result = |before, page, after| {
		state = Data.snapshot(before)?
		Ok(before == after and page.items().all(|view| state.things.any(|row| row.id == view.id)))
	}
}
