import pf.Api
import pf.Context
import pf.Handler
import pf.Query
import pf.Selection
import Data
import IntakePolicy
import ProposalTypes

Proposal :: [].{
	Output : {
		found : Bool,
		id : U64,
		requester : Str,
		status : Str,
		review_note : Str,
		contract_folder : Str,
		vendor : Str,
		business_reason : Str,
		budget_owner : Str,
		spend_cents : U64,
		spend_usd : Str,
		spend_period : Str,
		spend_start : Str,
		ramp_limit_cents : U64,
		ramp_usd : Str,
		ramp_cadence : Str,
		has_contract : Bool,
		contract_url : Str,
	}

	# Split the decimal representation to retain every cent with no floating-point conversion.
	usd : U64 -> Str
	usd = |amount| {
		digits = amount.to_str().to_utf8()
		cents = if digits.len() == 1 {
			"0${Str.from_utf8_lossy(digits)}"
		} else {
			Str.from_utf8_lossy(digits.drop_first(digits.len() - 2))
		}
		whole = if digits.len() <= 2 {
			"0"
		} else {
			grouped(digits.take_first(digits.len() - 2))
		}
		"$${whole}.${cents}"
	}

	grouped : List(U8) -> Str
	grouped = |digits| if digits.len() <= 3 {
		Str.from_utf8_lossy(digits)
	} else {
		cut = digits.len() - 3
		"${grouped(digits.take_first(cut))},${Str.from_utf8_lossy(digits.drop_first(cut))}"
	}

	empty : {} -> Output
	empty =
		|
			_,
		|
			{
				found: Bool.False,
				id: 0,
				requester: "",
				status: "",
				review_note: "",
				contract_folder: "",
				vendor: "",
				business_reason: "",
				budget_owner: "",
				spend_cents: 0,
				spend_usd: "",
				spend_period: "",
				spend_start: "",
				ramp_limit_cents: 0,
				ramp_usd: "",
				ramp_cadence: "",
				has_contract: Bool.False,
				contract_url: "",
			}

	definition =
		Api.query({
			audience: Employees,
			handler: Handler.local(handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})
			.verify_as_actor(IntakePolicy.reviewer)

	handle : Context, ProposalTypes.Input -> Query(Output)
	handle = |ctx, input| IntakePolicy.read({}).and_then(
		|configured| match configured {
			None => Query.succeed(empty({}))
			Some(settings) => {
				if !IntakePolicy.direct_reviewer(ctx, settings.value.reviewer) {
					return Query.succeed(empty({}))
				}
				Query.find(Selection.filter(Data.requests, Data.requests_number_equal(input.id))).map(
					|found| match found {
						None => empty({})
						Some(row) => {
							found: Bool.True,
							id: row.value.number,
							requester: row.value.requester,
							status: row.value.status,
							review_note: row.value.review_note,
							contract_folder: settings.value.contract_folder,
							vendor: row.value.vendor,
							business_reason: row.value.business_reason,
							budget_owner: row.value.budget_owner,
							spend_cents: row.value.spend_cents,
							spend_usd: usd(row.value.spend_cents),
							spend_period: row.value.spend_period,
							spend_start: row.value.spend_start,
							ramp_limit_cents: row.value.ramp_limit_cents,
							ramp_usd: usd(row.value.ramp_limit_cents),
							ramp_cadence: row.value.ramp_cadence,
							has_contract: row.value.has_contract,
							contract_url: row.value.contract_url,
						}
					},
				)
			}
		},
	)

	contract =
		{
			title: "Inspect the submitted terms",
			usage: {
				purpose: "Show the assigned reviewer an exact recorded proposal.",
				use_when: ["Reviewing terms before a decision."],
				avoid_when: [],
				preconditions: [],
				effects: [],
				result: "Stored terms for a matching visible request.",
			},
			inputs: { id: "Immutable request number." },
			outputs: {
				found: "The requested proposal is visible.",
				id: "The proposal number.",
				requester: "Authenticated submitter.",
				status: "Current decision status.",
				review_note: "Recorded review note.",
				contract_folder: "Operator-configured Drive folder. Confirm actual file location manually.",
				vendor: "Vendor name.",
				business_reason: "Business need and use of the purchase.",
				budget_owner: "Department whose existing allocation funds this vendor.",
				spend_usd: "Formatted USD vendor allocation.",
				spend_cents: "USD cents allocated to this vendor inside the existing department budget. Department total stays unchanged.",
				spend_period: "One-time or monthly Spend allocation: one_time or monthly.",
				spend_start: "Allocation start date as YYYY-MM-DD.",
				ramp_usd: "Formatted USD Ramp limit.",
				ramp_limit_cents: "Proposed Ramp control limit in USD cents, independent of the Spend allocation.",
				ramp_cadence: "One-time or monthly Ramp limit: one_time or monthly.",
				has_contract: "Whether there is an existing contract.",
				contract_url: "Canonical Drive file link when a contract exists, otherwise empty.",
			},
			example: |_| Ok({ input: { id: 1 }, output: empty({}) }),
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
			errors: [],
		}

	verify_input : Str, U64 -> Try(ProposalTypes.Input, Str)
	verify_input = |snapshot, _| match Data.verification_snapshot(snapshot)?.live.requests.last() {
		Ok(row) => Ok({ id: row.value.number })
		Err(_) => Ok({ id: 1 })
	}

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, out, after| {
		ctx = Api.verification_context(before)?
		decoded : Try({ id : U64 }, _)
		decoded = Json.parse(ctx.input)
		id = decoded.map_err(|_| "invalid review query input")?.id
		rows = Data.verification_snapshot(before)?.live.requests
		expected = rows.find_first(|r| r.value.number == id and ctx.actor == IntakePolicy.reviewer)
		verified = match expected {
			Err(_) => Json.to_str(out) == Json.to_str(empty({}))
			Ok(row) => out.found
				and out.id
					== id
					and out.requester
						== row.value.requester
						and out.status
							== row.value.status
							and out.review_note
								== row.value.review_note
								and out.contract_folder
									== IntakePolicy.contract_folder
									and out.vendor
										== row.value.vendor
										and out.business_reason
											== row.value.business_reason
											and out.budget_owner
												== row.value.budget_owner
												and out.spend_cents
													== row.value.spend_cents
													and out.spend_period
														== row.value.spend_period
														and out.spend_start
															== row.value.spend_start
															and out.ramp_limit_cents
																== row.value.ramp_limit_cents
																and out.ramp_cadence
																	== row.value.ramp_cadence
																	and out.has_contract
																		== row.value.has_contract
																		and out.contract_url == row.value.contract_url
		}
		Ok(before == after and verified)
	}
}

expect Proposal.usd(1) == "$0.01"
expect Proposal.usd(99) == "$0.99"
expect Proposal.usd(240_075) == "$2,400.75"
expect Proposal.usd(9_007_199_254_740_991) == "$90,071,992,547,409.91"
