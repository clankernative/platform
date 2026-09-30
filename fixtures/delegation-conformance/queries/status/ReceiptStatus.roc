import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Query
import ImportedContracts
import ReceiptStatusTypes

ReceiptStatus :: [].{
	Output : { status : Str }

	definition = Api.query({
		handler: Handler.prepared(prepare, handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	prepare : Context, ReceiptStatusTypes.Input -> Observe(Str)
	prepare = |_context, input| ImportedContracts.peer_identity_record_status({ id: input.receipt }).map(
		|status| match status {
			Pending => "pending"
			Success => "success"
			Refused => "refused"
			Blocked => "blocked"
			Unknown => "unknown"
		},
	)

	handle : Context, ReceiptStatusTypes.Input, Str -> Query(Output)
	handle = |_context, _input, status| Query.from_try(Ok({ status: status }))

	contract = {
		title: "Inspect a peer command receipt",
		usage: {
			purpose: "Read receiver progress under current authority.",
			use_when: ["Checking the later outcome of an accepted peer command."],
			avoid_when: ["Treating unknown as proof that the command never executed."],
			preconditions: ["Current permission to inspect this actor's receipt."],
			effects: [],
			result: "Pending, success, refused, blocked or unknown.",
		},
		inputs: { receipt: "An opaque receipt issued by this caller's peer command." },
		outputs: { status: "Authorized receiver progress." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : ReceiptStatusTypes.Input, output : Output }, Str)
	example = |_| Ok({ input: { receipt: "rcp_${Str.repeat("0", 64)}" }, output: { status: "unknown" } })

	verify_input : Str, U64 -> Try(ReceiptStatusTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ receipt: "rcp_${Str.repeat("0", 64)}" })

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and !output.status.is_empty())
}
