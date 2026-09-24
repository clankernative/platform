import pf.Handler
import ListLinksTypes
import pf.Api
import pf.Query
import pf.Context
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import LinkView
import Data

ListLinks :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)

	handle : Context, ListLinksTypes.Input -> Query(LinkView.Page)
	handle =
		|_context, input| Query.page(Data.all_links(input.after, input.limit)).map(|page| page.map(LinkView.from_row))

	contract =
		{
			title: "List links",
			usage: {
				purpose: "Browse visible links in a bounded page.",
				use_when: ["Finding a link."],
				avoid_when: ["Retrieving a known link by identifier."],
				preconditions: [],
				effects: [],
				result: "A page of links and a continuation cursor.",
			},
			inputs: { after: "Continuation cursor; empty starts the list.", limit: "The maximum page length." },
			outputs: {
				items: { description: "Visible links.", each: LinkView.fields },
				has_more: "Whether another page is available.",
				next_after: "The next continuation cursor.",
			},
			example: example,
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
			errors: [],

		}

	example : {} -> Try({ input : ListLinksTypes.Input, output : LinkView.Page }, Str)
	example = |_| {
		page = CollectionPage.from_parts([LinkView.example({})?], Bool.False, Cursor.start)?
		Ok({ input: { after: Cursor.start, limit: PageSize.default }, output: page })
	}

	verify_input : Str, U64 -> Try(ListLinksTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ after: Cursor.start, limit: PageSize.default })

	verify_result : Str, LinkView.Page, Str -> Try(Bool, Str)
	verify_result = |before, page, after| {
		state = Data.snapshot(before)?
		Ok(
			before
				== after
				and page.items().all(|view| state.links.any(|row| row.id == view.id and row.version == view.version)),
		)
	}
}
