import pf.Handler
import ReviseReportTypes
import pf.Api
import pf.Tx
import pf.Context
import pf.RowVersion
import ReportView
import Data
import Domains
import Selectors
import Reads
import Commands
import ReportScenarios

ReviseReport :: [].{
	definition =
		Api.command({
			handler: Handler.local(handle),
			contract,
			execution: Api.edit(
				Data.reports,
				Selectors.revise_input_report_id,
				Selectors.revise_input_expected_version,
				[
					Api.update(
						Data.reports,
						[
							Api.field(Selectors.reports_text),
							Api.field(Selectors.reports_ready),
							# A revision withdraws the previous announcement: the text
							# people were told about no longer exists.
							Api.field(Selectors.reports_announced),
							Api.field(Selectors.reports_bytes),
							Api.field(Selectors.reports_lines),
						],
					),
					Api.request(Commands.analyze),
				],
			),
			verification: { input: verify_input, check: verify_result },
		})

	handle : Context, ReviseReportTypes.Input -> Tx(ReportView.Saved)
	handle = |_context, input|
		Tx.get(Data.reports, input.report_id)
			.and_then(
				|
					report,
				|
					Tx.update(
						Data.reports,
						report,
						{
							..report.value,
							text: input.text,
							ready: Bool.False,
							announced: Bool.False,
							bytes: 0,
							lines: 0,
						},
					),
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
		title: "Revise a report",
		usage: {
			purpose: "Replace a report's text and request analysis of the replacement document.",
			use_when: ["The user requests an edit to an existing report."],
			avoid_when: ["Creating a new report or only reading existing content."],
			preconditions: ["Read current state first. Reconsider the edit if another change has occurred."],
			effects: ["Replaces the document, clears previous statistics, and queues fresh analysis atomically."],
			result: "The saved report identifier and committed revision; fresh analysis may still be running.",
		},
		inputs: {
			report_id: "The report to revise.",
			expected_version: "The revision read before preparing this edit.",
			text: "The replacement document. Newlines are preserved.",
		},
		outputs: ReportView.saved_fields,
		example: example,
		input_sources: |
			input,
		|
			[
				Api.read_source(input, Selectors.revise_input_report_id, Reads.detail, Selectors.detail_output_id),
				Api.read_source(
					input,
					Selectors.revise_input_expected_version,
					Reads.detail,
					Selectors.detail_output_version,
				),
			],
		follow_ups: [{ target: Api.read(Reads.detail), when: "Check ready before using the new analysis statistics." }],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : ReviseReportTypes.Input, output : ReportView.Saved }, Str)
	example = |_| {
		row = ReportView.example({})?
		text = Domains.document("Updated document")?
		next = RowVersion.from_u64(2).map_err(|_| "invalid example version")?
		Ok({ input: { report_id: row.id, expected_version: row.version, text }, output: { id: row.id, version: next } })
	}

	verify_input : Str, U64 -> Try(ReviseReportTypes.Input, Str)
	verify_input = |snapshot, seed| {
		row = ReportScenarios.first(snapshot)?
		text = Domains.document("Revised at ${row.version.to_u64().to_str()} / ${seed.to_str()}\nNew line")?
		Ok({ report_id: row.id, expected_version: row.version, text })
	}

	verify_result : Str, ReportView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old =
			Data.snapshot(before)?.reports.find_first(|row| row.id == saved.id).map_err(|_| "original report missing")?
		row =
			Data.snapshot(after)?
				.reports
				.find_first(|candidate| candidate.id == saved.id)
				.map_err(|_| "revised report missing")?
		Ok(
			row.version
				== saved.version
				and row.version.to_u64()
					== old.version.to_u64() + 1
					and row.value.text.to_str()
						!= old.value.text.to_str()
						and !row.value.ready and row.value.bytes == 0 and row.value.lines == 0,
		)
	}
}
