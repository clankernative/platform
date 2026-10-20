import pf.Api
import pf.Context
import pf.Handler
import pf.Tx
import CreateNoteTypes
import FixtureAccess
import Commands
import Data
import Errors

CreateNote :: [].{
	Output : { owner : Str, text : Str }

	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.notes)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, CreateNoteTypes.Input -> Tx(Output)
	handle = |context, input| if !FixtureAccess.authorized(context.actor()) {
		Tx.reject(Errors.create_denied)
	} else {
		Tx.create(Data.notes, { owner: context.actor(), text: input.text })
			.map(|row| { owner: row.value.owner, text: row.value.text })
	}

	contract = {
		title: "Create a fixture note",
		usage: {
			purpose: "Save a note as the disposable fixture operator.",
			use_when: ["Testing admitted command authorization and atomic rejection."],
			avoid_when: ["Production authentication or customer note storage."],
			preconditions: ["The actor is the fixture operator."],
			effects: ["Creates one note."],
			result: "The saved owner and text.",
		},
		inputs: { text: "The fixture note text." },
		outputs: { owner: "The authorized fixture operator.", text: "The saved note text." },
		example: |_| Ok({ input: { text: "example note" }, output: { owner: "developer", text: "example note" } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.create_denied],
	}

	verify_input : Str, U64 -> Try(CreateNoteTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ text: "Generated note ${seed.to_str()}" })

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.verification_snapshot(before)?.live
		next = Data.verification_snapshot(after)?.live
		Ok(
			next.notes.len() == old.notes.len() + 1
				and FixtureAccess.authorized(output.owner)
					and next.notes.any(|row| row.value.owner == output.owner and row.value.text == output.text),
		)
	}

	create_denied = Api.error({
		description: "Only the fixture operator may create notes.",
		recovery: "Use the authorized fixture actor.",
		verification: |_| Api.failed_command_as(
			Commands.create_note,
			Api.verification_principal("command-denied-synthetic"),
			verify_input,
		),
	})
}
