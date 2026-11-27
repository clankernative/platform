import Api
import Effects
import Resource

Ramp :: [].{
	create_fund_effect = Api.external("ramp.create_fund.v1")

	Interval : [Total, Monthly]

	Receipt : { fund_id : Str }

	create_fund : Resource, U64, Interval -> Effects(Receipt)
	create_fund = |resource, amount_cents, interval| {
		period = match interval {
			Total => "TOTAL"
			Monthly => "MONTHLY"
		}
		Effects.capability(
			"ramp.create_fund.v1",
			Json.to_str({ handle: Resource.token(resource), amount_cents, interval: period }),
		).and_then(
			|raw| {
				parsed : Try(Receipt, _)
				parsed = Json.parse(raw)
				Effects.from_host(parsed.map_err(|_| "invalid_ramp_fund_receipt"))
			},
		)
	}
}
