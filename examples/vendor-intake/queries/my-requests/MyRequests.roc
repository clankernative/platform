import pf.Api
import pf.Context
import pf.CollectionPage
import pf.Cursor
import pf.Handler
import pf.PageSize
import pf.Query
import pf.Selection
import Data
import IntakePolicy
import RequestSummary
import MyRequestsTypes

MyRequests :: [].{
	Output : { requests : CollectionPage(RequestSummary.Value), contract_folder : Str }

	definition =
		Api.query({
			audience: Employees,
			handler: Handler.local(handle),
			contract,
			verification: { input: |_, _| Ok({}), check: verify_result },
		})
			.verify_as_actor("ada@synthetic.example")

	handle : Context, MyRequestsTypes.Input -> Query(Output)
	handle = |ctx, _input| IntakePolicy.read({}).and_then(
		|configured| match configured {
			None => Query.succeed({ requests: CollectionPage.empty({}), contract_folder: "" })
			Some(settings) => {

				rows =
					Selection.filter(Data.requests, Data.requests_requester_equal(ctx.actor()))
						.order([Data.requests_number_desc])
						.paginate(Cursor.start, PageSize.default)
				Query.page(rows)
					.map(
						|
							page,
						|
							{
								requests: page.map(RequestSummary.from_row),
								contract_folder: settings.value.contract_folder,
							},
					)
			}
		},
	)

	contract = {
		title: "My vendor requests",
		usage: {
			purpose: "Show the twenty most recent requests made by the signed-in person.",
			use_when: ["Checking current request status."],
			avoid_when: [],
			preconditions: [],
			effects: [],
			result: "Request summaries.",
		},
		inputs: {},
		outputs: {
			requests: {
				description: "One bounded page of requests.",
				fields: {
					items: { description: "Requests in this page.", each: RequestSummary.fields },
					has_more: "Whether another page exists.",
					next_after: "Continuation cursor.",
				},
			},
			contract_folder: "Operator-configured Drive folder. Confirm actual file location manually.",
		},
		example: |
			_,
		|
			Ok({
				input: {},
				output: { requests: CollectionPage.empty({}), contract_folder: IntakePolicy.contract_folder },
			}),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, out, after| {
		actor = Api.verification_context(before)?.actor
		rows = Data.verification_snapshot(before)?.live.requests.keep_if(|r| r.value.requester == actor)
		expected = rows.len()
		Ok(
			before
				== after
				and out.contract_folder
					== IntakePolicy.contract_folder
					and out.requests.items().len()
						== (if expected > 20 20 else expected)
						and out
							.requests
							.items()
							.all(
								|
									item,
								|
									rows
										.any(
											|
												r,
											|
												r.value.number
													== item.id
													and r.value.vendor
														== item.vendor
														and r.value.status
															== item.status
															and r.value.review_note == item.review_note,
										),
							),
		)
	}
}
