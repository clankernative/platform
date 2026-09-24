import AnalyzeReportTypes
import pf.Api
import pf.Handler
import pf.Observe
import pf.Tx
import pf.Ref
import pf.RowVersion
import pf.Context
import Data
import Selectors
import ReportView
import ReportScenarios
import Commands

# Analysis is an internal command. Its captured input is computed outside the
# decision transaction, then applied only while the document revision still matches.
AnalyzeReport :: [].{
	definition = Api.command({
		handler: Handler.prepared(prepare, decide),
		contract,
		execution: Api.internal(
			Api.edit(
				Data.reports,
				Selectors.analyze_input_report_id,
				Selectors.analyze_input_expected_version,
				[
					Api.update(
						Data.reports,
						[
							Api.field(Selectors.reports_ready),
							Api.field(Selectors.reports_bytes),
							Api.field(Selectors.reports_lines),
						],
					),
					Api.request(Commands.notify),
				],
			),
		),
		verification: { input: verify_input, check: verify_result },
	})

	prepare : Context, AnalyzeReportTypes.Input -> Observe(AnalyzeReportTypes.Result)
	prepare = |_context, input| {
		text = input.text.to_str()
		Observe.value({ bytes: text.count_utf8_bytes(), lines: text.split_on("\n").len() })
	}

	decide : Context, AnalyzeReportTypes.Input, AnalyzeReportTypes.Result -> Tx(ReportView.Saved)
	decide = |_context, input, statistics|
		Tx.get(Data.reports, input.report_id)
			.and_then(
				|
					report,
				|
					Tx.update(
						Data.reports,
						report,
						{ ..report.value, ready: Bool.True, bytes: statistics.bytes, lines: statistics.lines },
					),
			)
			.and_then(
				|changed| {
					if statistics.lines == 2 {
						match input.text.to_str().split_on("\n").get(1) {
							Err(_) => Tx.succeed(changed)
							Ok(raw) => match Ref.from_str(raw) {
								Err(_) => Tx.succeed(changed)
								Ok(id) => Tx.update(
									Data.reports,
									{ ..changed, id, version: RowVersion.one },
									changed.value,
								)
									.map(|_| changed)
							}
						}
					} else {
						Tx.succeed(changed)
					}
				},
			)
			.and_then(
				|
					report,
				|
					Commands.notify
						.request(Data.reports, report, { report_id: report.id, expected_version: report.version })
						.map(|_| { id: report.id, version: report.version }),
			)

	contract = {
		errors: [],
		title: "Analyze a report revision",
		usage: {
			purpose: "Compute document statistics and apply them to the captured report revision.",
			use_when: ["A submit or revise command requests analysis in its transaction."],
			avoid_when: ["Reading existing statistics or applying results to a different revision."],
			preconditions: ["The captured document revision is still current."],
			effects: ["Marks the captured revision ready and records its byte and line counts atomically."],
			result: "The report identifier and the revision containing the computed statistics.",
		},
		inputs: {
			report_id: "The report to analyze.",
			expected_version: "The captured document revision.",
			text: "The captured document text.",
		},
		outputs: ReportView.saved_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : AnalyzeReportTypes.Input, output : ReportView.Saved }, Str)
	example = |_| {
		report = ReportView.example({})?
		Ok({
			input: { report_id: report.id, expected_version: report.version, text: report.text },
			output: { id: report.id, version: report.version },
		})
	}

	verify_input : Str, U64 -> Try(AnalyzeReportTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		report = ReportScenarios.first(snapshot)?
		Ok({ report_id: report.id, expected_version: report.version, text: report.value.text })
	}

	verify_result : Str, ReportView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old =
			Data.snapshot(before)?
				.reports
				.find_first(|report| report.id == saved.id)
				.map_err(|_| "original report missing")?
		report =
			Data.snapshot(after)?.reports.find_first(|row| row.id == saved.id).map_err(|_| "analyzed report missing")?
		Ok(
			report.value.ready
				and report.version
					== saved.version
					and report.value.text.to_str()
						== old.value.text.to_str()
						and report.value.bytes
							== old.value.text.to_str().count_utf8_bytes()
							and report.value.lines == old.value.text.to_str().split_on("\n").len(),
		)
	}
}
