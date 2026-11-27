import pf.Table

Models :: [].{
	Revision := { number : U64, html : Str, author : Str }.{
		table : Table(Revision, _)
		table = Table.keyed(|row| { by_number: Table.unique({ number: row.number }) })
	}

	Request := {
		number : U64,
		requester : Str,
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
		status : Str,
		review_note : Str,
		reviewer : Str,
		checked_folder : Bool,
	}.{
		is_eq : Request, Request -> Bool
		is_eq =
			|
				left,
				right,
			|
				[
					left.number == right.number,
					left.requester == right.requester,
					left.vendor == right.vendor,
					left.business_reason == right.business_reason,
					left.budget_owner == right.budget_owner,
					left.spend_cents == right.spend_cents,
					left.spend_period == right.spend_period,
					left.spend_start == right.spend_start,
					left.ramp_limit_cents == right.ramp_limit_cents,
					left.ramp_cadence == right.ramp_cadence,
					left.has_contract == right.has_contract,
					left.contract_url == right.contract_url,
					left.status == right.status,
					left.review_note == right.review_note,
					left.reviewer == right.reviewer,
					left.checked_folder == right.checked_folder,
				]
					.all(|equal| equal)

		table : Table(Request, _)
		table =
			Table.keyed(
				|
					row,
				|
					{
						by_number: Table.unique({ number: row.number }),
						by_requester_number: Table.non_unique({ requester: row.requester, number: row.number }),
						by_status_number: Table.non_unique({ status: row.status, number: row.number }),
					},
			)
	}

	Setting := { install_key : U64, product_owners : Str, reviewer : Str, contract_folder : Str }.{
		is_eq : Setting, Setting -> Bool
		is_eq =
			|
				left,
				right,
			|
				[
					left.install_key == right.install_key,
					left.product_owners == right.product_owners,
					left.reviewer == right.reviewer,
					left.contract_folder == right.contract_folder,
				]
					.all(|equal| equal)

		table : Table(Setting, _)
		table = Table.keyed(|row| { by_install: Table.unique({ install_key: row.install_key }) })
	}
}
