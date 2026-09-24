import pf.Api
import pf.Context
import pf.Handler
import pf.Query
import pf.Tx
import pf.Cursor
import pf.PageSize
import pf.Selection
import pf.Predicate
import pf.Model
import SweepReportsTypes
import Data
import Commands
import Models

# Reconciliation. Reports already requests analysis on submit and announces a
# ready revision through notify, but nothing re-examines state after the fact: a
# report whose notification was never accepted stays ready and unannounced
# forever, and no one finds out. This is the smallest honest use of a schedule --
# it repairs state rather than producing any of its own.
SweepReports :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		# Internal: a schedule is its only caller. No HTTP, form or MCP entrypoint,
		# so declaring the schedule cannot open a second way in.
		execution: Api.internal(Api.current_state([Api.request(Commands.notify)])),
		verification: { input: verify_input, check: verify_result },
	})

	# A bounded page, not a scan. The schedule runs again, so a sweep that reaches
	# its bound simply continues on the next occurrence; it does not need to finish.
	handle : Context, SweepReportsTypes.Input -> Tx(SweepReportsTypes.Result)
	handle = |_context, _input| Query.page(unannounced)
		.as_transaction()
		.and_then(
			|page| announce_each(page.items()).map(
				|reconciled| { reconciled, remaining: page.has_more() },
			),
		)

	unannounced : Selection(Models.Report)
	unannounced = Selection.filter(
		Data.reports,
		Predicate.all([Data.reports_ready_equal(Bool.True), Data.reports_announced_equal(Bool.False)]),
	)
		.order([Data.reports_id_asc])
		.paginate(Cursor.start, PageSize.default)

	# Requesting notify for each row, in order. Recursion rather than a fold: the
	# list idiom in this dialect has no walk, and each step must stay in Tx.
	announce_each : List(Model.Entity(Models.Report)) -> Tx(U64)
	announce_each = |rows| match rows {
		[] => Tx.succeed(0)
		[row, .. as rest] => Commands.notify
			.request(Data.reports, row, { report_id: row.id, expected_version: row.version })
			.and_then(|_| announce_each(rest).map(|count| count + 1))
	}

	contract = {
		errors: [],
		title: "Reconcile unannounced ready reports",
		usage: {
			purpose: "Request a notification for every report that is ready but was never announced.",
			use_when: ["A schedule fires. This command has no other caller."],
			avoid_when: ["Announcing one known report; request notify directly instead."],
			preconditions: ["None. An occurrence with nothing to reconcile is a successful empty sweep."],
			effects: ["Requests the notify command for each report in one bounded page."],
			result: "How many notifications were requested, and whether reports remain for the next occurrence.",
		},
		inputs: {},
		outputs: {
			reconciled: "Notifications requested by this occurrence.",
			remaining: "Whether unannounced reports remain beyond this page; the next occurrence continues.",
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : SweepReportsTypes.Input, output : SweepReportsTypes.Result }, Str)
	example = |_| Ok({ input: {}, output: { reconciled: 1, remaining: Bool.False } })

	verify_input : Str, U64 -> Try(SweepReportsTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({})

	# A sweep leaves no report ready-and-unannounced within the page it examined,
	# and never announces one that was not ready.
	verify_result : Str, SweepReportsTypes.Result, Str -> Try(Bool, Str)
	verify_result = |before, result, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		pending = |state| state.reports.keep_if(|row| row.value.ready and !row.value.announced).len()
		Ok(
			next.reports.len() == old.reports.len() and result.reconciled <= pending(old)
				and (result.remaining or pending(next) <= pending(old)),
		)
	}
}
