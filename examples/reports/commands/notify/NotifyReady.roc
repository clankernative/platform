import pf.Api
import pf.Context
import pf.Handler
import pf.Observe
import pf.Query
import pf.Tx
import pf.Effects
import pf.Notifications
import NotifyReadyTypes
import Data
import Selectors
import ReportView
import ReportScenarios

NotifyReady :: [].{
	Facts : { recipient : Notifications.Recipient }

	Decision : { recipient : Notifications.Recipient, topic : Str, body : Str, ready : Bool }

	definition = Api.command({
		handler: Handler.effects(prepare, decide, deliver, complete),
		contract,
		# Api.edit declares the concurrency target; the write itself is a separate
		# effect and is declared here. announced is the only field this command
		# may change.
		execution: Api.internal(
			Api.edit(
				Data.reports,
				Selectors.notify_input_report_id,
				Selectors.notify_input_expected_version,
				[Notifications.send_effect, Api.update(Data.reports, [Api.field(Selectors.reports_announced)])],
			),
		),
		verification: { input: verify_input, check: verify_result },
	})

	# A dependent preparation: first authorize the local report read, then resolve
	# the requester's recipient through the platform's shared notification capability.
	prepare : Context, NotifyReadyTypes.Input -> Observe(Facts)
	prepare = |context, input| Observe.local(Query.get(Data.reports, input.report_id))
		.and_then(
			|_| Notifications.resolve(context).map(
				|recipient| { recipient: recipient },
			),
		)

	# This read and the durable effect intent belong to one local transaction.
	decide : Context, NotifyReadyTypes.Input, Facts -> Tx(Decision)
	decide = |_context, input, facts| Tx.get(Data.reports, input.report_id)
		.map(
			|
				report,
			|
				{
					recipient: facts.recipient,
					topic: report.id.to_str(),
					body: "Report '${
						report
							.value
							.title
							.to_str()
					}' is ready: ${report.value.bytes.to_str()} bytes, ${report.value.lines.to_str()} lines.",
					ready: report.value.ready,
				},
		)

	deliver : Decision -> Effects(Notifications.Receipt)
	deliver = |decision| if decision.ready {
		Notifications.send(decision.recipient, decision.topic, decision.body)
	} else {
		Effects.value({ id: "", status: "skipped" })
	}

	# The platform stores delivery progress; the app needs no delivery-status table.
	# Recording the announcement is this app's own state, though: it is what makes
	# "ready but never announced" answerable, and so what the sweep reconciles
	# against. Only an accepted receipt counts -- a skipped one announced nothing.
	complete : Context, NotifyReadyTypes.Input, Decision, Notifications.Receipt -> Tx(Notifications.Receipt)
	complete = |_context, input, _decision, receipt| if receipt.status == "accepted" {
		Tx.get(Data.reports, input.report_id).and_then(
			|report| Tx.update(Data.reports, report, { ..report.value, announced: Bool.True })
				.map(|_| receipt),
		)
	} else {
		Tx.succeed(receipt)
	}

	contract = {
		errors: [],
		title: "Notify the report requester",
		usage: {
			purpose: "Notify the requester that the captured report revision is ready.",
			use_when: ["Analysis commits a ready report."],
			avoid_when: ["Sending notifications for an obsolete or unanalyzed document."],
			preconditions: ["The captured revision is current when the effect is accepted."],
			effects: [
				"Records an external notification intent and submits it through the shared notification capability.",
			],
			result: "The provider receipt and acceptance status. Acceptance does not imply delivery.",
		},
		inputs: { report_id: "The analyzed report.", expected_version: "The captured ready revision." },
		outputs: { id: "The provider receipt, empty when skipped.", status: "Accepted or skipped." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : NotifyReadyTypes.Input, output : Notifications.Receipt }, Str)
	example = |_| {
		report = ReportView.example({})?
		Ok({
			input: { report_id: report.id, expected_version: report.version },
			output: { id: "msg_example", status: "accepted" },
		})
	}

	verify_input : Str, U64 -> Try(NotifyReadyTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		report = ReportScenarios.first(snapshot)?
		Ok({ report_id: report.id, expected_version: report.version })
	}

	# Notifying is no longer state-neutral: an accepted receipt records the
	# announcement. The postcondition is that exactly that changed -- the row count
	# is stable, and no report's announced flag moved from true back to false.
	verify_result : Str, Notifications.Receipt, Str -> Try(Bool, Str)
	verify_result = |before, receipt, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		announced = |state| state.reports.keep_if(|row| row.value.announced).len()
		Ok(
			(receipt.status == "accepted" or receipt.status == "skipped")
				and next.reports.len() == old.reports.len()
					and announced(next) >= announced(old)
						and (receipt.status == "accepted" or before == after)
							and old
								.reports
								.all(
									|row|
										!row.value.announced
											or next.reports.any(|later| later.id == row.id and later.value.announced),
								),
		)
	}
}
