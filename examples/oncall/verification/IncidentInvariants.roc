import pf.Api
import Data

IncidentInvariants :: [].{
	incidents = Api.invariant(
		Data.incidents,
		"Incident status is recognized and escalation rung stays within its allowed range.",
		Data.snapshot,
		|state|
			state.incidents.all(|row|
				(row.value.status == "Open" or row.value.status == "Acknowledged" or row.value.status == "Resolved")
					and row.value.rung >= 0
					and row.value.rung <= 3,
			),
	)
}
