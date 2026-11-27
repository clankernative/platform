import pf.Api
import pf.Context
import pf.Cursor
import pf.PageSize
import pf.GoogleWorkspace
import pf.Observe
import pf.Handler
import pf.Tx
import Data
import Commands
import Errors
import IntakePolicy
import ProposalTerms
import SubmitRequestTypes

SubmitRequest :: [].{
	definition = Api.command({
		audience: Employees,
		handler: Handler.prepared(prepare, handle),
		execution: Api.current_state([Api.create(Data.requests)]),
		contract,
		verification: { input: |_snapshot, seed| Ok(ProposalTerms.sample(seed)), check: verify_result },
	}).require_all_rows(Data.requests).observes("google_workspace.group_member.v1").verify_as_actor(
		"ada@synthetic.example",
	)

	prepare : Context, SubmitRequestTypes.Input -> Observe(GoogleWorkspace.MembershipOutcome)
	prepare = |context, _input| Observe.local(IntakePolicy.read({})).and_then(
		|configured| match configured {
			None => Observe.value(NotMember)
			Some(settings) => GoogleWorkspace.group_member(context, settings.value.product_owners, context.actor())
		},
	)

	handle : Context, SubmitRequestTypes.Input, GoogleWorkspace.MembershipOutcome -> Tx(SubmitRequestTypes.Output)
	handle = |context, input, membership| match membership {
		Member => {
			if !ProposalTerms.valid(input) {
				return Tx.reject(Errors.invalid_proposal)
			}
			Tx.count(Data.all_requests(Cursor.start, PageSize.default))
				.and_then(
					|
						count,
					|
						Tx.create(
							Data.requests,
							{
								number: count + 1,
								requester: context.actor(),
								status: "pending",
								review_note: "",
								reviewer: "",
								checked_folder: Bool.False,
								vendor: input.vendor,
								business_reason: input.business_reason,
								budget_owner: input.budget_owner,
								spend_cents: input.spend_cents,
								spend_period: input.spend_period,
								spend_start: input.spend_start,
								ramp_limit_cents: input.ramp_limit_cents,
								ramp_cadence: input.ramp_cadence,
								has_contract: input.has_contract,
								contract_url: input.contract_url,
							},
						)
							.map(|created| { id: created.value.number }),
				)
		}
		_ => Tx.reject(Errors.membership_required)
	}

	contract = {
		title: "Submit a vendor request",
		usage: {
			purpose: "Record proposed vendor terms for individual review.",
			use_when: ["A product owner requests a vendor allocation."],
			avoid_when: [],
			preconditions: ["Current product-owner group membership and complete terms."],
			effects: ["Appends one pending request."],
			result: "Immutable request number.",
		},
		inputs: {
			vendor: "Vendor name.",
			business_reason: "Business need and use of the purchase.",
			budget_owner: "Department whose existing allocation funds this vendor.",
			spend_cents: "USD cents allocated to this vendor inside the existing department budget. Department total stays unchanged.",
			spend_period: "One-time or monthly Spend allocation: one_time or monthly.",
			spend_start: "Allocation start date as YYYY-MM-DD.",
			ramp_limit_cents: "Proposed Ramp control limit in USD cents, independent of the Spend allocation.",
			ramp_cadence: "One-time or monthly Ramp limit: one_time or monthly.",
			has_contract: "Whether there is an existing contract.",
			contract_url: "Canonical Drive file link when a contract exists, otherwise empty.",
		},
		outputs: { id: "Immutable request number." },
		example: |_| Ok({ input: ProposalTerms.sample(42), output: { id: 1 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.membership_required, Errors.invalid_proposal],
	}

	verify_result : Str, SubmitRequestTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, out, after| {
		context = Api.verification_context(before)?
		parsed : Try(
			{
				vendor : Str,
				business_reason : Str,
				budget_owner : Str,
				spend_cents : U64,
				spend_period : Str,
				spend_start : Str,
				ramp_limit_cents : U64,
				ramp_cadence : Str,
				has_contract : Bool,
				contract_url : Str,
			},
			_,
		)
		parsed = Json.parse(context.input)
		input = parsed.map_err(|_| "invalid submitted terms")?
		old = Data.verification_snapshot(before)?
		new = Data.verification_snapshot(after)?
		created = new.live.requests.find_first(|row| row.value.number == out.id).map_err(|_| "missing submission")?
		Ok(
			out.id
				== old.live.requests.len() + 1
				and new.live.requests.len()
					== out.id
					and created.version.to_u64()
						== 1
						and created.value.status
							== "pending"
							and created.value.requester
								== context.actor
								and created.value.vendor
									== input.vendor
									and created.value.business_reason
										== input.business_reason
										and created.value.budget_owner
											== input.budget_owner
											and created.value.spend_cents
												== input.spend_cents
												and created.value.spend_period
													== input.spend_period
													and created.value.spend_start
														== input.spend_start
														and created.value.ramp_limit_cents
															== input.ramp_limit_cents
															and created.value.ramp_cadence
																== input.ramp_cadence
																and created.value.has_contract
																	== input.has_contract
																	and created.value.contract_url
																		== input.contract_url
																		and old
																			.live
																			.requests
																			.all(
																				|
																					row,
																				|
																					new
																						.live
																						.requests
																						.any(
																							|
																								other,
																							|
																								other.id
																									== row.id
																									and other.value
																										== row.value
																										and row.version
																											== other
																												.version,
																						),
																			)
																			and new.deleted.requests.is_empty(),
		)
	}

	invalid_proposal = Api.error({
		description: "The vendor terms or contract link are invalid.",
		recovery: "Check amounts, periods, date and Drive file link.",
		verification: |_| Api.failed_command_as(
			Commands.submit_request,
			Api.verification_principal("ada@synthetic.example"),
			|_snap, seed| {
				input = ProposalTerms.sample(seed)
				Ok({ ..input, has_contract: Bool.True, contract_url: "" })
			},
		),
	})

	membership_required =
		Api.error({
			description: "Directory membership does not authorize submission.",
			recovery: "Ask the product-owners group administrator to confirm your membership.",
			verification: |
				_,
			|
				Api.failed_command_as(
					Commands.submit_request,
					Api.verification_principal("calendar-reader@synthetic.example"),
					|_snap, seed| Ok(ProposalTerms.sample(seed)),
				),
		})
}
