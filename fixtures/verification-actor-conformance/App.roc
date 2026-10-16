import CreateNote
import CountNotes
import NoteRoutes
import NoteInvariants

App :: [].{
	definition = {
		namespace: "verifiers",
		operations: { create_note: CreateNote.definition, count_notes: CountNotes.definition },
		pages: { notes: NoteRoutes.count.register() },
		properties: { notes: NoteInvariants.notes },
		errors: { create_denied: CreateNote.create_denied, count_denied: CountNotes.count_denied },
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
