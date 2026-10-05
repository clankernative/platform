import StockAvailable
import ReserveStock
import StockInvariants

App :: [].{
	definition = {
		namespace: "stock_ledger",
		operations: { available: StockAvailable.definition, reserve: ReserveStock.definition },
		pages: {},
		properties: { reservations: StockInvariants.conservation },
		errors: { insufficient_stock: ReserveStock.insufficient_stock },
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
