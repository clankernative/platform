import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import ReserveStockTypes
import Stock
import Data
import Commands
import Errors

ReserveStock :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.reservations)]),
		verification: { input: verify_input, check: verify_result },
	}).cross_app({ version: 1 })

	handle : Context, ReserveStockTypes.Input -> Tx(ReserveStockTypes.Output)
	handle = |context, input| Tx.collect(Stock.owned(context.actor()), 100).and_then(
		|rows| {
			available = Stock.initial - Stock.reserved(rows)
			if input.quantity == 0 or input.quantity > available {
				Tx.reject(Errors.insufficient_stock)
			} else {
				Tx.create(Data.reservations, { owner: context.actor(), quantity: input.quantity })
					.map(|_| { reserved: input.quantity, available: available - input.quantity })
			}
		},
	)

	contract = {
		title: "Reserve actor-owned stock",
		usage: {
			purpose: "Atomically reserve units under the receiver's business policy.",
			use_when: ["Fulfilling a stock request."],
			avoid_when: ["Reserving another actor's stock."],
			preconditions: ["The actor has enough available units."],
			effects: ["Creates one actor-owned reservation or refuses without changing stock."],
			result: "Reserved units and remaining stock.",
		},
		inputs: { quantity: "Positive units requested from the effective actor's stock." },
		outputs: { reserved: "Units reserved by this command.", available: "Remaining actor-owned units." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.insufficient_stock],
	}

	example : {} -> Try({ input : ReserveStockTypes.Input, output : ReserveStockTypes.Output }, Str)
	example = |_| Ok({ input: { quantity: 1 }, output: { reserved: 1, available: 99 } })

	verify_input : Str, U64 -> Try(ReserveStockTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ quantity: 1 })

	verify_result : Str, ReserveStockTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.reservations.len()
				== old.reservations.len() + 1
				and Stock.reserved(next.reservations) == Stock.reserved(old.reservations) + output.reserved,
		)
	}

	insufficient_stock = Api.error({
		description: "The requested quantity is zero or exceeds available stock.",
		recovery: "Request a positive quantity within the available stock.",
		verification: |_| Api.failed_command(Commands.reserve, |_snapshot, _seed| Ok({ quantity: 101 })),
	})
}
