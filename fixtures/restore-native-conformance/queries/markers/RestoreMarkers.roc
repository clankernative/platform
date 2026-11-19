import pf.Api
import pf.Context
import pf.CollectionPage
import pf.Cursor
import pf.Handler
import pf.PageSize
import pf.Query
import RestoreMarkersTypes
import Data

RestoreMarkers :: [].{
	Output : { count : U64, page : CollectionPage({ note : Str }) }

	definition = Api.query({
		audience: Employees,
		handler: Handler.local(handle),
		contract: {
			title: "Read complete public restore markers",
			usage: {
				purpose: "Compare fixture state selected before backup with state after a separately authorized restore.",
				use_when: ["Checking committed public marker preservation under a genuine native installation."],
				avoid_when: ["Treating this query or a build result as backup, restore, or native authority."],
				preconditions: [
					"Current ordinary read permission and complete marker visibility; at most 100 markers.",
				],
				effects: [],
				result: "Every visible public marker, or capacity refusal without truncation.",
			},
			inputs: {},
			outputs: {
				count: "The complete number of public markers.",
				page: {
					description: "Complete public marker set.",
					fields: {
						items: {
							description: "All public markers.",
							each: { note: "A public use_ label; no credential material." },
						},
						has_more: "Always false for a successful complete collection.",
						next_after: "The start cursor; no omitted suffix.",
					},
				},
			},
			example: |_| Ok({ input: {}, output: { count: 0, page: CollectionPage.empty({}) } }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({}),
			check: |before, output, after| {
				state = Data.verification_snapshot(before)?.live
				markers = state.use_receipts.map(|row| row.value.note)
				actual = output.page.items().map(|row| row.note)
				Ok(
					before == after and output.count == markers.len() and actual.len() == markers.len()
						and !output.page.has_more() and output.page.next_after().is_start()
							and markers
								.all(
									|
										label,
									|
										markers.keep_if(|value| value == label).len()
											== actual.keep_if(|value| value == label).len(),
								),
				)
			},
		},
	}).require_all_rows(Data.use_receipts)

	handle : Context, RestoreMarkersTypes.Input -> Query(Output)
	handle = |_context, _input| Query.collect(Data.all_use_receipts(Cursor.start, PageSize.default), 100)
		.map(|rows| { count: rows.len(), page: CollectionPage.complete(rows.map(|row| { note: row.value.note })) })
}
