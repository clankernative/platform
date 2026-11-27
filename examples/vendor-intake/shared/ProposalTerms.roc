import SubmitRequestTypes

ProposalTerms :: [].{
	text : Str, U64 -> Bool
	text =
		|value, limit| !value.trim().is_empty() and value.count_utf8_bytes() <= limit and !value.to_utf8().contains(0)

	cadence : Str -> Bool
	cadence = |value| value == "monthly" or value == "one_time"

	digits : Str, U64 -> Bool
	digits = |value, len| value.count_utf8_bytes() == len and value.to_utf8().all(|byte| byte >= 48 and byte <= 57)

	date : Str -> Bool
	date = |value| match value.split_on("-") {
		[y, m, d] => {
			if !digits(y, 4) or !digits(m, 2) or !digits(d, 2) {
				return Bool.False
			}
			match (U64.from_str(y), U64.from_str(m), U64.from_str(d)) {
				(Ok(year), Ok(month), Ok(day)) => {
					leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
					limit = match month {
						2 => if leap 29 else 28
						4 | 6 | 9 | 11 => 30
						_ => 31
					}
					year > 0 and month >= 1 and month <= 12 and day >= 1 and day <= limit
				}
				_ => Bool.False
			}
		}
		_ => Bool.False
	}

	drive_file : Str -> Bool
	drive_file = |url| match url.split_on("/") {
		["https:", "", "drive.google.com", "file", "d", id, "view"] => {
			size = id.count_utf8_bytes()
			size
				>= 1
				and size
					<= 200
					and id
						.to_utf8()
						.all(
							|
								b,
							|
								(b >= 65 and b <= 90)
									or (b >= 97 and b <= 122) or (b >= 48 and b <= 57) or b == 45 or b == 95,
						)
		}
		_ => Bool.False
	}

	valid : SubmitRequestTypes.Input -> Bool
	valid = |input| text(input.vendor, 128) and text(input.business_reason, 2000) and text(input.budget_owner, 200)
		and input.spend_cents
			> 0
			and input.spend_cents
				<= 9_007_199_254_740_991
				and input.ramp_limit_cents > 0 and input.ramp_limit_cents <= 9_007_199_254_740_991
					and cadence(input.spend_period) and cadence(input.ramp_cadence) and date(input.spend_start)
						and (
							if input.has_contract {
								drive_file(input.contract_url)
							} else {
								input.contract_url.is_empty()
							}
						)

	sample : U64 -> SubmitRequestTypes.Input
	sample = |seed| {
		vendor: "Example Vendor ${seed.to_str()}",
		business_reason: "Renew design software",
		budget_owner: "Design",
		spend_cents: 240_000,
		spend_period: "one_time",
		spend_start: "2028-02-29",
		ramp_limit_cents: 20_000,
		ramp_cadence: "monthly",
		has_contract: seed % 2 == 0,
		contract_url: if seed % 2 == 0 "https://drive.google.com/file/d/synthetic_contract/view" else "",
	}
}

expect ProposalTerms.date("2028-02-29")
expect !ProposalTerms.date("2027-02-29")
expect !ProposalTerms.date("2027-04-31")
expect ProposalTerms.drive_file("https://drive.google.com/file/d/abc_123-DEF/view")
expect !ProposalTerms.drive_file("https://drive.google.com.evil.example/file/d/abc/view")
expect !ProposalTerms.drive_file("https://drive.google.com/drive/folders/abc")
