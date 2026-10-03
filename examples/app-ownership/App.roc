import CheckOwnership
import SetOwner
import OwnershipInvariants

App :: [].{
	definition = {
		namespace: "app_ownership",
		operations: { check: CheckOwnership.definition, set_owner: SetOwner.definition },
		pages: {},
		properties: { ownerships: OwnershipInvariants.valid },
		errors: { invalid_owner: SetOwner.invalid_owner },
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
