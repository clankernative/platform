import pf.Api
import Stock
import Data

StockInvariants :: [].{
	conservation = Api.invariant(
		Data.reservations,
		"Every owner's reservations conserve the initial stock and have positive quantities.",
		Data.snapshot,
		|
			state,
		|
			state
				.reservations
				.all(
					|
						row,
					|
						!row.value.owner.is_empty()
							and row.value.quantity
								> 0
								and Stock.reserved(
									state.reservations.keep_if(|other| other.value.owner == row.value.owner),
								)
									<= Stock.initial,
				),
	)
}
