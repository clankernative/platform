import pf.Api
import Data
import ProposalTerms

RequestInvariants :: [].{
	requests = Api.invariant(
		Data.requests,
		"Each request has exactly its original terms and either one pending state or one final decision by its assigned reviewer.",
		Data.snapshot,
		|state| state.requests.all(
			|row| {
				item = row.value
				proposal =
					{
						vendor: item.vendor,
						business_reason: item.business_reason,
						budget_owner: item.budget_owner,
						spend_cents: item.spend_cents,
						spend_period: item.spend_period,
						spend_start: item.spend_start,
						ramp_limit_cents: item.ramp_limit_cents,
						ramp_cadence: item.ramp_cadence,
						has_contract: item.has_contract,
						contract_url: item.contract_url,
					}
				item.number
					> 0
					and item.number
						<= state.requests.len()
						and !item.requester.is_empty() and ProposalTerms.valid(proposal) and (
							if item.status == "pending" {
								row.version.to_u64()
									== 1
									and item.reviewer.is_empty()
										and item.review_note.is_empty() and !item.checked_folder
							} else {
								row.version.to_u64()
									== 2
									and (item.status == "approved" or item.status == "returned")
										and state.settings.any(|setting| setting.value.reviewer == item.reviewer)
											and ProposalTerms.text(item.review_note, 1000)
												and item.checked_folder
													== (item.has_contract and item.status == "approved")
							}
						)
			},
		),
	)
}
