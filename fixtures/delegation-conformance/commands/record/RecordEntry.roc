import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import RecordEntryTypes
import IdentityView
import Data

RecordEntry :: [].{
	Output : { identity : IdentityView.Value, id : Str, note : Str }

	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.entries)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, RecordEntryTypes.Input -> Tx(Output)
	handle = |context, input| Tx.create(Data.entries, { actor: context.actor(), note: input.note })
		.map(|row| { identity: IdentityView.from_context(context), id: row.id.to_str(), note: row.value.note })

	contract = {
		title: "Record the effective command actor",
		usage: {
			purpose: "Persist one actor-owned row to test authenticated command admission, execution and retries.",
			use_when: ["Checking that synchronous and asynchronous commands preserve sealed identity and write once."],
			avoid_when: ["Reading identity without changing state."],
			preconditions: [],
			effects: ["Creates exactly one entry owned by the effective actor."],
			result: "The created identifier, note and the sealed context used by the command.",
		},
		inputs: { note: "Text stored unchanged in the new entry." },
		outputs: {
			identity: { description: "Sealed context of the writing command.", fields: IdentityView.fields },
			id: "Identifier of the created entry.",
			note: "The persisted note.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : RecordEntryTypes.Input, output : Output }, Str)
	example =
		|
			_,
		|
			Ok({
				input: { note: "example" },
				output: { identity: IdentityView.sample({}), id: "example-entry", note: "example" },
			})

	verify_input : Str, U64 -> Try(RecordEntryTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ note: "entry-${seed.to_str()}" })

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.entries.len() == old.entries.len() + 1 and IdentityView.valid(output.identity)
				and next
					.entries
					.any(
						|
							row,
						|
							row.id.to_str()
								== output.id
								and row.value.actor == output.identity.actor and row.value.note == output.note,
					)
					and old.entries.all(
						|previous| next.entries.any(
							|row| row.id == previous.id
								and row.value.actor == previous.value.actor and row.value.note == previous.value.note,
						),
					),
		)
	}
}
