import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import pf.Observe
import pf.Audit
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import HistoryTypes

# The pattern an application uses to publish its own history: a query reads it
# through `Audit.history`, and whoever the operator grants this query is the
# audience. The platform audit log itself remains its owners' alone.
History :: [].{
	Entry : {
		sequence : I64,
		operation : Str,
		actor : Str,
		initiator : Str,
		outcome : Str,
		at : I64,
		records : Str,
		change_count : U64,
	}

	Output : CollectionPage(Entry)

	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})

	prepare : Context, HistoryTypes.Input -> Observe(CollectionPage(Audit.Entry))
	prepare =
		|_context, input| Audit.history({ operations: ["delegation.record"], after: input.after, limit: input.limit })

	handle : Context, HistoryTypes.Input, CollectionPage(Audit.Entry) -> Query(Output)
	handle = |_context, _input, page| Query.from_try(Ok(page.map(view)))

	view : Audit.Entry -> Entry
	view = |entry| {
		sequence: entry.sequence,
		operation: entry.operation,
		actor: entry.actor,
		initiator: entry.initiator,
		outcome: entry.outcome,
		at: entry.at,
		records: Str.join_with(entry.changes.map(|change| change.record_id), " "),
		change_count: entry.change_count,
	}

	contract = {
		title: "Read this application's own entry history",
		usage: {
			purpose: "Exercise Audit.history: the application's own completed record commands, newest first.",
			use_when: ["Checking that an app reads its own history and that the grant decides who may."],
			avoid_when: ["Reading the platform audit log, which belongs to the application's owners."],
			preconditions: ["The operator grants this query the audit.history.v1 observation."],
			effects: [],
			result: "A page of completed record invocations with the entries each wrote.",
		},
		inputs: {
			after: "Use an empty cursor to start; pass next_after unchanged for the next older page.",
			limit: "The maximum number of entries in this page, at most 50.",
		},
		outputs: {
			items: {
				description: "Completed record invocations, newest first.",
				each: {
					sequence: "Position in this application's history; larger is newer.",
					operation: "The operation that completed.",
					actor: "Whom the invocation acted for.",
					initiator: "Who authenticated the invocation.",
					outcome: "success or failure.",
					at: "Completion time in Unix seconds.",
					records: "Identifiers of the rows the invocation wrote, separated by spaces.",
					change_count: "How many rows the invocation wrote.",
				},
			},
			has_more: "Whether an older page is available.",
			next_after: "The continuation cursor. Follow has_more to decide whether to request another page.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : HistoryTypes.Input, output : Output }, Str)
	example = |_| {
		row = {
			sequence: 1,
			operation: "delegation.record",
			actor: "alice",
			initiator: "alice",
			outcome: "success",
			at: 1,
			records: "example-entry",
			change_count: 1,
		}
		page = CollectionPage.from_parts([row], Bool.False, Cursor.start)?
		Ok({ input: { after: Cursor.start, limit: PageSize.default }, output: page })
	}

	verify_input : Str, U64 -> Try(HistoryTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ after: Cursor.start, limit: PageSize.default })

	verify_result : Str, Output, Str -> Try(Bool, Str)
	verify_result = |before, page, after| {
		Ok(
			before
				== after
				and page
					.items()
					.all(
						|
							entry,
						|
							entry.operation
								== "delegation.record"
								and !entry.actor.is_empty() and !entry.records.is_empty() and entry.change_count == 1,
					),
		)
	}
}
