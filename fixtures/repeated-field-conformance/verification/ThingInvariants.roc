import pf.Api
import Data

ThingInvariants :: [].{
	things = Api.invariant(Data.things, "Every stored row has an owner.", Data.snapshot, |state|
		state.things.all(|row| !row.value.owner.is_empty()))
}
