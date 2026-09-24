import pf.Handler
import pf.Observe
import pf.Notifications
import GetReportTypes
import pf.Api
import pf.Query
import pf.Context
import ReportView
import Data
import Selectors
import Reads
import Commands
import ReportScenarios

GetReport :: [].{
	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})

	prepare : Context, GetReportTypes.Input -> Observe(Notifications.Delivery)
	prepare = |context, input| Observe.local(Query.get(Data.reports, input.report_id))
		.and_then(|_| Notifications.latest(context, input.report_id.to_str()))

	handle : Context, GetReportTypes.Input, Notifications.Delivery -> Query(ReportView.Detail)
	handle =
		|
			_context,
			input,
			delivery,
		|
			Query.get(Data.reports, input.report_id)
				.map(|report| ReportView.with_delivery(ReportView.from_row(report), delivery))

	contract = {
		errors: [],
		title: "Get a report",
		usage: {
			purpose: "Retrieve a report's current document, revision, and analysis statistics.",
			use_when: [
				"Inspecting a known report, checking analysis readiness, or obtaining the current revision before editing.",
			],
			avoid_when: ["Discovering report identifiers; browse the report list first."],
			preconditions: ["The current actor must be permitted to read the report."],
			effects: [],
			result: "The report and its current revision. Use statistics only when ready is true.",
		},
		inputs: { report_id: "The identifier of the report to retrieve." },
		outputs: ReportView.detail_fields,
		example: example,
		input_sources: |
			input,
		|
			[
				Api.read_source(input, Selectors.detail_input_report_id, Reads.list, Selectors.list_output_items_id),
				Api.write_source(input, Selectors.detail_input_report_id, Commands.submit, Selectors.submit_output_id),
			],
		follow_ups: [
			{
				target: Api.write(Commands.revise),
				when: "Only when the user requests an edit; pass the current revision.",
			},
		],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : GetReportTypes.Input, output : ReportView.Detail }, Str)
	example = |_| {
		row = ReportView.example({})?
		Ok({
			input: { report_id: row.id },
			output: ReportView.with_delivery(row, { id: "", status: "none", count: 0 }),
		})
	}

	verify_input : Str, U64 -> Try(GetReportTypes.Input, Str)
	verify_input = |snapshot, _seed| Ok({ report_id: ReportScenarios.first(snapshot)?.id })

	verify_result : Str, ReportView.Detail, Str -> Try(Bool, Str)
	verify_result = |before, view, after| {
		row =
			Data.snapshot(before)?
				.reports
				.find_first(|candidate| candidate.id == view.id)
				.map_err(|_| "report missing")?
		Ok(
			before
				== after
				and view.version
					== row.version
					and view.title.to_str()
						== row.value.title.to_str()
						and view.text.to_str()
							== row.value.text.to_str()
							and view.ready
								== row.value.ready
								and view.bytes == row.value.bytes and view.lines == row.value.lines,
		)
	}
}
