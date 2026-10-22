import pf.Handler
import SearchReportsTypes
import pf.Api
import pf.Query
import pf.Context
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import ReportSearch
import ReportView
import Data

SearchReports :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, SearchReportsTypes.Input -> Query(ReportSearch.Result)
	handle = |_context, input|
	# One bounded page, like every Reports read: never a whole-table scan.
		Query.page(Data.all_reports(Cursor.start, PageSize.maximum))
			.map(
				|page| {
					term: input.term,
					matches: CollectionPage.complete(
						page.items()
							.keep_if(|row| title_matches(row.value.title.to_str(), input.term))
							.map(ReportSearch.from_row),
					),
					searched_all: !page.has_more(),
				},
			)

	contract = {
		errors: [],
		title: "Search report titles",
		usage: {
			purpose: "Find visible reports whose title contains a literal search term.",
			use_when: ["Searching report titles without changing the paginated directory."],
			avoid_when: ["Browsing the report directory or retrieving a known report by identifier."],
			preconditions: [],
			effects: [],
			result: "The raw search term, matching reports among the first 100 visible reports ordered by report ID, and whether that bounded scan covered every visible report.",
		},
		inputs: {
			term: "A raw, literal, case-sensitive substring matched against report titles; an empty string matches every visible title.",
		},
		outputs: ReportSearch.fields,
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : SearchReportsTypes.Input, output : ReportSearch.Result }, Str)
	example = |_| {
		report = ReportView.example({})?
		summary = { id: report.id, version: report.version, title: report.title, ready: report.ready }
		Ok({
			input: { term: "Weekly" },
			output: { term: "Weekly", matches: CollectionPage.complete([summary]), searched_all: Bool.True },
		})
	}

	verify_input : Str, U64 -> Try(SearchReportsTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		state = Data.verification_snapshot(snapshot)?.live
		term = match state.reports.first() {
			Ok(row) => row.value.title.to_str()
			Err(_) => ""
		}
		Ok({ term: term })
	}

	title_matches : Str, Str -> Bool
	title_matches = |title, term| title.contains(term)

	verify_result : Str, ReportSearch.Result, Str -> Try(Bool, Str)
	verify_result = |before, result, after| {
		state = Data.verification_snapshot(before)?.live
		scanned = state.reports.take_first(100)
		expected = scanned.keep_if(|row| title_matches(row.value.title.to_str(), result.term))
		synthetic_cases =
			title_matches("Weekly report", "Weekly")
				and title_matches("Weekly report", "")
					and !title_matches("Weekly report", "weekly")
						and !title_matches("Weekly report", "missing")
		Ok(
			before == after
				and synthetic_cases
					and result.searched_all == (state.reports.len() <= scanned.len())
						and result.matches.items().map(|view| view.id) == expected.map(|row| row.id)
							and !result.matches.has_more() and result.matches.next_after() == Cursor.start
								and result.matches.items().all(
									|view|
										expected.any(
											|row|
												row.id == view.id
													and row.version == view.version
														and row.value.title.to_str() == view.title.to_str()
															and row.value.ready == view.ready,
										),
								),
		)
	}
}
