import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Tx
import pf.Effects
import pf.Ref
import ImportedContracts
import RequestStockTypes
import Models
import Data
import Selectors

RequestStock :: [].{
	Decision : { id : Ref(Models.Request), quantity : U64, available : U64 }

	definition = Api.command({
		handler: Handler.effects(prepare, decide, deliver, complete),
		contract,
		execution: Api.current_state([
			Api.create(Data.requests),
			Api.update(Data.requests, [Api.field(Selectors.requests_receipt)]),
			Api.external("app.send.v1"),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	prepare : Context, RequestStockTypes.Input -> Observe(U64)
	prepare = |_context, _input| ImportedContracts.stock_ledger_available({}).map(|stock| stock.available)

	decide : Context, RequestStockTypes.Input, U64 -> Tx(Decision)
	decide =
		|
			context,
			input,
			available,
		|
			Tx.create(Data.requests, { owner: context.actor(), quantity: input.quantity, receipt: "" })
				.map(|row| { id: row.id, quantity: input.quantity, available })

	deliver : Decision -> Effects(ImportedContracts.StockLedgerReserveReceipt)
	deliver = |decision| ImportedContracts.stock_ledger_reserve_send({ quantity: decision.quantity })

	complete :
		Context,
		RequestStockTypes.Input,
		Decision,
		ImportedContracts.StockLedgerReserveReceipt ->
			Tx(RequestStockTypes.Output)
	complete =
		|
			_context,
			_input,
			decision,
			receipt,
		|
			Tx.get(Data.requests, decision.id)
				.and_then(
					|
						row,
					|
						Tx.update(Data.requests, row, { ..row.value, receipt: receipt.id })
							.map(|_| { receipt: receipt.id, observed_available: decision.available }),
				)

	contract = {
		title: "Request a stock reservation",
		usage: {
			purpose: "Record an owned request and send a typed reservation command.",
			use_when: ["Requesting stock through a separate application."],
			avoid_when: ["Treating acceptance as business success."],
			preconditions: ["Current actor permission in both apps."],
			effects: ["Creates one request, accepts one peer command and records the acceptance receipt."],
			result: "The receipt and advisory availability observed before sending.",
		},
		inputs: { quantity: "Requested units. The stock ledger decides whether to refuse." },
		outputs: { receipt: "Durable receiver acceptance.", observed_available: "Advisory stock read before sending." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : RequestStockTypes.Input, output : RequestStockTypes.Output }, Str)
	example = |_| Ok({ input: { quantity: 1 }, output: { receipt: "rcp_example", observed_available: 100 } })

	verify_input : Str, U64 -> Try(RequestStockTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ quantity: 1 })

	verify_result : Str, RequestStockTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.requests.len()
				== old.requests.len() + 1
				and output.receipt.starts_with("rcp_") and next.requests.any(|row| row.value.receipt == output.receipt),
		)
	}
}
