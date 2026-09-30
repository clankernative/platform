import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Tx
import pf.Effects
import ImportedContracts
import SendEntryTypes

SendEntry :: [].{
	Output : { receipt : Str }

	definition = Api.command({
		handler: Handler.effects(prepare, decide, deliver, complete),
		contract,
		execution: Api.current_state([Api.external("app.send.v1")]),
		verification: { input: verify_input, check: verify_result },
	})

	prepare : Context, SendEntryTypes.Input -> Observe({})
	prepare = |_context, _input| Observe.value({})

	decide : Context, SendEntryTypes.Input, {} -> Tx(Str)
	decide = |_context, input, _facts| Tx.succeed(input.note)

	deliver : Str -> Effects(ImportedContracts.PeerIdentityRecordReceipt)
	deliver = |note| ImportedContracts.peer_identity_record_send({ note: note })

	complete : Context, SendEntryTypes.Input, Str, ImportedContracts.PeerIdentityRecordReceipt -> Tx(Output)
	complete = |_context, _input, _decision, receipt| Tx.succeed({ receipt: receipt.id })

	contract = {
		title: "Send an actor-owned entry to the peer",
		usage: {
			purpose: "Exercise durable typed command acceptance across app hosts.",
			use_when: ["Checking acknowledgement loss and receiver deduplication."],
			avoid_when: ["Requiring the peer's completed business result in this transaction."],
			preconditions: ["Both apps independently permit the effective human actor."],
			effects: ["Durably accepts one peer record command."],
			result: "A durable acceptance receipt. The receiver executes separately.",
		},
		inputs: { note: "The actor-owned note." },
		outputs: { receipt: "The opaque acceptance receipt." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : SendEntryTypes.Input, output : Output }, Str)
	example = |_| Ok({ input: { note: "example" }, output: { receipt: "rcp_example" } })

	verify_input : Str, U64 -> Try(SendEntryTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ note: "send-${seed.to_str()}" })

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and output.receipt.starts_with("rcp_"))
}
