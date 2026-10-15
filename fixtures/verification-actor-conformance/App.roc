import CreateNote
import CountNotes
import NoteInvariants

App :: [].{
	definition = {
		namespace: "verifiers",
		operations: { create_note: CreateNote.definition, count_notes: CountNotes.definition },
		pages: {},
		properties: { notes: NoteInvariants.notes },
		errors: { create_denied: CreateNote.create_denied, count_denied: CountNotes.count_denied },
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
