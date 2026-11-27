SubmitRequestTypes :: [].{
	Input := {
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
	}

	Output : { id : U64 }
}
