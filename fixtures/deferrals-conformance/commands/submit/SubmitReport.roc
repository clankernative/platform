import pf.Handler
import SubmitReportTypes
import pf.Api
import pf.Tx
import pf.Context
import pf.Model
import pf.Ref
import pf.RowVersion
import Models
import ReportView
import Data
import Domains
import Selectors
import Reads
import Commands

SubmitReport :: [].{
	definition =
		Api.command({
			handler: Handler.local(handle),
			contract,
			execution: Api.current_state([
				Api.create(Data.reports),
				Api.update(Data.reports, [Api.field(Selectors.reports_text)]),
				Api.request(Commands.analyze),
				Api.defer(Commands.analyze),
			]),
			verification: { input: verify_input, check: verify_result },
		})

	handle : Context, SubmitReportTypes.Input -> Tx(ReportView.Saved)
	handle = |context, input| {
		value : Models.Report
		value = {
			title: input.title,
			text: input.text,
			owner: context.actor(),
			ready: Bool.False,
			announced: Bool.False,
			bytes: 0,
			lines: 0,
		}
		if input.title.to_str() == "forged" {
			match Ref.from_str(input.text.to_str()) {
				Err(_) => Tx.create(Data.reports, value).map(|row| { id: row.id, version: row.version })
				Ok(id) => {
					forged : Model.Entity(Models.Report)
					forged = { id, version: RowVersion.one, created_at: context.now(), value }
					Commands.analyze
						.request(
							Data.reports,
							forged,
							{ report_id: forged.id, expected_version: forged.version, text: input.text },
						)
						.map(|_| { id: id, version: RowVersion.one })
				}
			}
		} else if input.title.to_str() == "defer"
			or input.title.to_str() == "for"
				or input.title.to_str() == "long_delay"
					or input.title.to_str() == "past"
						or input.title.to_str() == "far"
							or input.title.to_str() == "both"
			{
				due =
					if input.title.to_str() == "past" {
						context.now() - 1
					} else if input.title.to_str() == "far" {
						context.now() + 2_592_001
					} else {
						context.now() + 10
					}
				delay : I64
				delay = if input.title.to_str() == "long_delay" {
					2_592_001
				} else {
					10
				}
				Tx.create(Data.reports, value)
					.and_then(
						|
							report,
						|
							if input.title.to_str() == "both" {
								Commands.analyze
									.request(
										Data.reports,
										report,
										{
											report_id: report.id,
											expected_version: report.version,
											text: report.value.text,
										},
									)
									.and_then(
										|_|
											Commands.analyze
												.defer_until(
													Data.reports,
													report,
													{
														report_id: report.id,
														expected_version: report.version,
														text: report.value.text,
													},
													due,
												)
												.map(|_| { id: report.id, version: report.version }),
									)
							} else if input.title.to_str() == "for" or input.title.to_str() == "long_delay" {
								Commands.analyze
									.defer_for(
										Data.reports,
										report,
										{
											report_id: report.id,
											expected_version: report.version,
											text: report.value.text,
										},
										delay,
									)
									.map(|_| { id: report.id, version: report.version })
							} else {
								Commands.analyze
									.defer_until(
										Data.reports,
										report,
										{
											report_id: report.id,
											expected_version: report.version,
											text: report.value.text,
										},
										due,
									)
									.map(|_| { id: report.id, version: report.version })
							},
					)
			} else {
				Tx.create(Data.reports, value)
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
								.and_then(
									|_| {
										if input.title.to_str() == "after_request" {
											match Domains.document(
												input.title.to_str().concat(" changed after request"),
											) {
												Ok(text) => Tx.update(Data.reports, report, { ..report.value, text })
													.map(|changed| { id: changed.id, version: changed.version })
												Err(_) => Tx.succeed({ id: report.id, version: report.version })
											}
										} else {
											Tx.succeed({ id: report.id, version: report.version })
										}
									},
								),
					)
			}
	}

	contract = {
		errors: [],
		title: "Submit a report",
		usage: {
			purpose: "Create a report owned by the current actor and request document analysis.",
			use_when: ["The user supplies a title and document for a new report."],
			avoid_when: ["Changing an existing report or only checking its analysis."],
			preconditions: [],
			effects: ["Creates the report and records a due analysis command in the same transaction."],
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
