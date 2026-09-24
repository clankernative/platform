import pf.Handler
import SubmitReportTypes
import pf.Api
import pf.Tx
import pf.Context
import ReportView
import Data
import Domains
import Reads
import Commands

SubmitReport :: [].{
	definition =
		Api.command({
			handler: Handler.local(handle),
			contract,
			execution: Api.current_state([Api.create(Data.reports), Api.request(Commands.analyze)]),
			verification: { input: verify_input, check: verify_result },
		})

	handle : Context, SubmitReportTypes.Input -> Tx(ReportView.Saved)
	handle = |context, input|
		Tx.create(
			Data.reports,
			{
				title: input.title,
				text: input.text,
				owner: context.actor(),
				ready: Bool.False,
				announced: Bool.False,
				bytes: 0,
				lines: 0,
			},
		)
			.and_then(
				|
					report,
				|
					Commands.analyze
						.request(
							Data.reports,
							report,
							{ report_id: report.id, expected_version: report.version, text: report.value.text },
						)
						.map(|_| { id: report.id, version: report.version }),
			)

	contract = {
		errors: [],
		title: "Submit a report",
		usage: {
			purpose: "Create a report owned by the current actor and request document analysis.",
			use_when: ["The user supplies a title and document for a new report."],
			avoid_when: ["Changing an existing report or only checking its analysis."],
			preconditions: [],
			effects: ["Creates the report and queues analysis in the same transaction."],
			result: "The new report identifier and committed revision. Analysis may still be running.",
		},
		inputs: { title: "The title for the new report.", text: "The document to analyze. Newlines are preserved." },
		outputs: ReportView.saved_fields,
		example: example,
		input_sources: |_| [],
		follow_ups: [{ target: Api.read(Reads.detail), when: "Check ready before using analysis statistics." }],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : SubmitReportTypes.Input, output : ReportView.Saved }, Str)
	example = |_| {
		row = ReportView.example({})?
		Ok({ input: { title: row.title, text: row.text }, output: { id: row.id, version: row.version } })
	}

	verify_input : Str, U64 -> Try(SubmitReportTypes.Input, Str)
	verify_input = |_snapshot, seed| {
		title = Domains.title("Generated report ${seed.to_str()}")?
		text = Domains.document("Generated text ${seed.to_str()}\nSecond line")?
		Ok({ title, text })
	}

	verify_result : Str, ReportView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		row = next.reports.find_first(|candidate| candidate.id == saved.id).map_err(|_| "created report missing")?
		Ok(
			next.reports.len()
				== old.reports.len() + 1
				and row.version == saved.version and !row.value.ready and row.value.bytes == 0 and row.value.lines == 0,
		)
	}
}
