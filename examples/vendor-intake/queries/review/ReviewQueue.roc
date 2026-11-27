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
import ReviewQueueTypes

ReviewQueue :: [].{
	Output : { requests : CollectionPage(RequestSummary.Value), contract_folder : Str }

	definition =
		Api.query({
			audience: Employees,
			handler: Handler.local(handle),
			contract,
			verification: { input: |_, _| Ok({ after: Cursor.start }), check: verify_result },
		})
			.verify_as_actor(IntakePolicy.reviewer)

	handle : Context, ReviewQueueTypes.Input -> Query(Output)
	handle = |ctx, input| IntakePolicy.read({}).and_then(
		|configured| match configured {
			None => Query.succeed({ requests: CollectionPage.empty({}), contract_folder: "" })
			Some(settings) => {
				if !IntakePolicy.direct_reviewer(ctx, settings.value.reviewer) {
					return Query.succeed(
						{ requests: CollectionPage.empty({}), contract_folder: settings.value.contract_folder },
					)
				}
				rows =
					Selection.filter(Data.requests, Data.requests_status_equal("pending"))
						.order([Data.requests_number_desc])
						.paginate(input.after, PageSize.default)
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
		title: "Pending vendor reviews",
		usage: {
			purpose: "Page through pending requests as the assigned reviewer.",
			use_when: ["Checking current request status."],
			avoid_when: [],
			preconditions: [],
			effects: [],
			result: "Request summaries.",
		},
		inputs: { after: "Start with the empty cursor; use the returned cursor for the next page." },
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
				input: { after: Cursor.start },
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
		rows = Data.verification_snapshot(before)?.live.requests.keep_if(|r| r.value.status == "pending")
		expected = if actor == IntakePolicy.reviewer rows.len() else 0
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
