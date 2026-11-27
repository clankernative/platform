import pf.Api
import pf.Context
import pf.Handler
import pf.Query
import pf.Selection
import Data
import Errors
import Reads
import ReadRevisionTypes

ReadRevision :: [].{
	definition = Api.query({
		audience: Employees,
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	}).require_all_rows(Data.revisions)

	handle : Context, ReadRevisionTypes.Input -> Query(ReadRevisionTypes.Output)
	handle =
		|_context, input| Query.find(Selection.filter(Data.revisions, Data.revisions_number_equal(input.id))).and_then(
			|found| match found {
				Some(row) => Query.succeed({ html: row.value.html })
				None => Query.from_try(Err(Errors.missing_revision))
			},
		)

	contract = {
		title: "Read a vendor intake page revision",
		usage: {
			purpose: "Retrieve the exact saved source selected by a pinned preview.",
			use_when: ["Opening a revision or loading its source for editing."],
			avoid_when: [],
			preconditions: ["The revision was saved in this app."],
			effects: [],
			result: "The original HTML, including whitespace.",
		},
		inputs: { id: "The positive revision number returned by saving." },
		outputs: { html: "The exact HTML stored in that revision." },
		example: |_| Ok({ input: { id: 1 }, output: { html: "<h1>Vendor intake</h1>" } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.missing_revision],
	}

	verify_input : Str, U64 -> Try(ReadRevisionTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		rows = Data.verification_snapshot(snapshot)?.live.revisions
		row = rows.first().map_err(|_| "save a revision first")?
		Ok({ id: row.value.number })
	}

	verify_result : Str, ReadRevisionTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		request : Try({ id : U64 }, _)
		request = Json.parse(Api.verification_context(before)?.input)
		number = request.map_err(|_| "invalid revision verification input")?.id
		expected = Data.verification_snapshot(before)?.live.revisions.find_first(|row| row.value.number == number)
			.map_err(|_| "selected revision missing")?
		Ok(before == after and output.html == expected.value.html)
	}

	missing_revision = Api.error({
		description: "No saved revision has that number.",
		recovery: "Open a link with a revision number returned by saving.",
		verification: |_| Api.failed_query(Reads.revision, |_snapshot, _seed| Ok({ id: 0 })),
	})
}
