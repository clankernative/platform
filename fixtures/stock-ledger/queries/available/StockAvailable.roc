import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import StockAvailableTypes
import Stock

StockAvailable :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)
			.cross_app({ version: 1 })

	handle : Context, StockAvailableTypes.Input -> Query(StockAvailableTypes.Output)
	handle =
		|
			context,
			_input,
		|
			Query.collect(Stock.owned(context.actor()), 100)
				.map(
					|
						rows,
					|
						{
							available: Stock.initial - Stock.reserved(rows),
							reserved: Stock.reserved(rows),
							count: rows.len(),
						},
				)

	contract = {
		title: "Read available stock",
		usage: {
			purpose: "Read the effective actor's remaining stock.",
			use_when: ["Planning a reservation."],
			avoid_when: ["Assuming a read reserves stock."],
			preconditions: [],
			effects: [],
			result: "Remaining units from the actor's initial 100 units.",
		},
		inputs: {},
		outputs: {
			available: "Currently unreserved units owned by the effective actor.",
			reserved: "Total reserved units from the complete actor-owned set.",
			count: "Number of actor-owned reservations in that complete set.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : StockAvailableTypes.Input, output : StockAvailableTypes.Output }, Str)
	example = |_| Ok({ input: {}, output: { available: 100, reserved: 0, count: 0 } })

	verify_input : Str, U64 -> Try(StockAvailableTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, StockAvailableTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and output.available <= Stock.initial)
}
