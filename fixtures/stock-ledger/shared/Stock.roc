import pf.Selection
import Data

Stock :: [].{
	initial : U64
	initial = 100

	owned = |actor| Selection.filter(Data.reservations, Data.reservations_owner_equal(actor))

	reserved = |rows| rows.fold(0, |total, row| total + row.value.quantity)
}
