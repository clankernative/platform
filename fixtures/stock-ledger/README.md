# Stock ledger

An independently owned reservation service. Each actor has 100 units of stock.
The exported `stock_ledger.available` query reports owned availability, reserved
quantity and reservation count. The exported `stock_ledger.reserve` command
atomically collects the complete bounded owned state, refuses zero or excessive
quantities and creates one owned reservation otherwise.

The app's invariant checks positive reservations and conservation per owner. A
separate reference model in platform qualification compares its public API
observations with the command schedule; it does not call these transitions to
compute the expected result. See `../request-desk/README.md` for the caller and
campaign.
