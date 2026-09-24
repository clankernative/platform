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
		execution: Api.internal(
			Api.edit(
				Data.reports,
				Selectors.notify_input_report_id,
				Selectors.notify_input_expected_version,
				[Notifications.send_effect],
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
			.and_then(|first| Notifications.send(decision.recipient, decision.topic, "Follow-up linked to ${first.id}"))
	} else {
		Effects.value({ id: "", status: "skipped" })
	}

	# The platform stores delivery progress; the app needs no delivery-status table.
	complete : Context, NotifyReadyTypes.Input, Decision, Notifications.Receipt -> Tx(Notifications.Receipt)
	complete = |_context, _input, _decision, receipt| Tx.succeed(receipt)

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

	verify_result : Str, Notifications.Receipt, Str -> Try(Bool, Str)
	verify_result =
		|before, receipt, after| Ok(before == after and (receipt.status == "accepted" or receipt.status == "skipped"))
}
