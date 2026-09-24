import pf.Handler
import ListReportsTypes
import pf.Api
import pf.Query
import pf.Context
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import ReportView
import Data
import Selectors
import Reads

ListReports :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)

	handle : Context, ListReportsTypes.Input -> Query(ReportView.Page)
	handle =
		|
			_context,
			input,
		| Query.page(Data.all_reports(input.after, input.limit)).map(|page| page.map(ReportView.from_row))

	contract = {
		errors: [],
		title: "List reports",
		usage: {
			purpose: "Browse reports visible to the current actor in a bounded page ordered by report ID.",
			use_when: ["Finding a report or browsing reports before selecting one."],
			avoid_when: ["Retrieving a known report by its identifier."],
			preconditions: [],
			effects: [],
			result: "A page of visible reports with a continuation cursor and analysis state.",
		},
		inputs: {
			after: "Use an empty cursor to start; pass next_after unchanged for another page.",
			limit: "The maximum number of reports in this page.",
		},
		outputs: {
			items: { description: "Reports visible to the current actor.", each: ReportView.fields },
			has_more: "Whether another page is available.",
			next_after: "The continuation cursor. Follow has_more to decide whether to request another page.",
		},
		example: example,
		input_sources: |
			input,
		| [Api.read_source(input, Selectors.list_input_after, Reads.list, Selectors.list_output_next_after)],
		follow_ups: [{ target: Api.read(Reads.detail), when: "After selecting a report from the page." }],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : ListReportsTypes.Input, output : ReportView.Page }, Str)
	example = |_| {
		row = ReportView.example({})?
		page = CollectionPage.from_parts([row], Bool.False, Cursor.start)?
		Ok({ input: { after: Cursor.start, limit: PageSize.default }, output: page })
	}

	verify_input : Str, U64 -> Try(ListReportsTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ after: Cursor.start, limit: PageSize.default })

	verify_result : Str, ReportView.Page, Str -> Try(Bool, Str)
	verify_result = |before, page, after| {
		state = Data.snapshot(before)?
		Ok(
			before
				== after
				and page.items().all(|view| state.reports.any(|row| row.id == view.id and row.version == view.version)),
		)
	}
}
