import pf.Api
import Ownership
import Data

OwnershipInvariants :: [].{
	valid = Api.invariant(
		Data.ownerships,
		"Assignments have valid identifiers and unique app/principal pairs.",
		Data.snapshot,
		|state| state.ownerships.all(
			|row| Ownership.valid_app_id(row.value.app_id)
				and Ownership.valid_principal(row.value.principal)
					and state.ownerships.keep_if(
						|other| other.value.app_id == row.value.app_id
							and other.value.principal == row.value.principal,
					).len() == 1,
		),
	)
}
