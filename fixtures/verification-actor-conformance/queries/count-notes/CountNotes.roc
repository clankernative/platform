import pf.Api
import pf.Context
import pf.Cursor
import pf.Handler
import pf.PageSize
import pf.Query
import CountNotesTypes
import FixtureAccess
import Data
import Reads
import Errors

CountNotes :: [].{
	Output : { count : U64 }

	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	}).require_all_rows(Data.notes)

	handle : Context, CountNotesTypes.Input -> Query(Output)
	handle = |context, _input| if !FixtureAccess.authorized(context.actor()) {
		Query.from_try(Err(Errors.count_denied))
	} else {
		Query.collect(Data.all_notes(Cursor.start, PageSize.default), 128)
			.map(|rows| { count: rows.len() })
	}

	contract = {
		title: "Count fixture notes",
		usage: {
			purpose: "Count all notes visible to the disposable fixture operator.",
			use_when: ["Testing admitted query authorization and rejection."],
			avoid_when: ["Production authentication or unbounded collection."],
			preconditions: ["The actor is the fixture operator and has complete note visibility."],
			effects: [],
			result: "The complete note count, bounded at 128 rows without truncation.",
		},
		inputs: {},
		outputs: { count: "The number of saved fixture notes." },
		example: |_| Ok({ input: {}, output: { count: 0 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.count_denied],
	}

	verify_input : Str, U64 -> Try(CountNotesTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		state = Data.verification_snapshot(before)?.live
		Ok(before == after and output.count == state.notes.len())
	}

	count_denied = Api.error({
		description: "Only the fixture operator may count notes.",
		recovery: "Use the authorized fixture actor.",
		verification: |_| Api.failed_query_as(
			Reads.count_notes,
			Api.verification_principal("query-denied-synthetic"),
			verify_input,
		),
	})
}
