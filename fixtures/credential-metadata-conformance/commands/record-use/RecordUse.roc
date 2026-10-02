import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import RecordUseTypes
import Data

RecordUse :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract: {
			title: "Record a credential API use",
			usage: {
				purpose: "Exercise an ordinary product write under a frozen credential grant.",
				use_when: ["Checking credential command admission and retry."],
				avoid_when: [],
				preconditions: ["Current ordinary write permission and a live credential grant."],
				effects: ["Creates one public reference record."],
				result: "Whether the record was committed.",
			},
			inputs: { note: "A public use_ receipt label recorded by this product command." },
			outputs: { recorded: "True on commit." },
			example: |_| Ok({ input: { note: "use_example" }, output: { recorded: Bool.True } }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		execution: Api.current_state([Api.create(Data.use_receipts)]),
		verification: {
			input: |_snapshot, seed| Ok({ note: "use_${seed.to_str()}" }),
			check: |before, output, after| {
				old = Data.snapshot(before)?
				next = Data.snapshot(after)?
				Ok(output.recorded and next.use_receipts.len() == old.use_receipts.len() + 1)
			},
		},
	}).credential_ready()

	handle : Context, RecordUseTypes.Input -> Tx({ recorded : Bool })
	handle = |_context, input| Tx.create(Data.use_receipts, { note: input.note }).map(|_| { recorded: Bool.True })
}
