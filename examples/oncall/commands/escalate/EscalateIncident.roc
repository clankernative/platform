import EscalateIncidentTypes
import pf.Api
import pf.Handler
import pf.Tx
import pf.Context
import pf.Ref
import Data
import Commands
import Selectors

EscalateIncident :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.internal(
			Api.current_state([
				Api.update(Data.incidents, [Api.field(Selectors.incidents_rung)]),
				Api.defer(Commands.escalate),
			]),
		),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, EscalateIncidentTypes.Input -> Tx(EscalateIncidentTypes.Result)
	handle = |_context, input|
		Tx.get(Data.incidents, input.incident_id)
			.and_then(|incident|
				if incident.value.status != "Open" {
					Tx.succeed({
						escalated: Bool.False,
						rung: incident.value.rung,
						reason: if incident.value.status == "Acknowledged" { "acknowledged" } else { "resolved" },
					})
				} else if incident.value.rung >= 3 {
					Tx.succeed({ escalated: Bool.False, rung: incident.value.rung, reason: "max_rung" })
				} else {
					Tx.update(Data.incidents, incident, { ..incident.value, rung: incident.value.rung + 1 })
						.and_then(|changed|
							Commands.escalate
								.defer_for(
									Data.incidents,
									changed,
									{ incident_id: changed.id },
									300.I64,
								)
								.map(|_| { escalated: Bool.True, rung: changed.value.rung, reason: "escalated" }),
						)
				},
			)

	contract = {
		errors: [],
		title: "Escalate an open incident",
		usage: {
			purpose: "Raise the escalation rung for an incident that remains open.",
			use_when: ["The deferred escalation attempt is admitted."],
			avoid_when: ["Changing incident status or manually opening a new incident."],
			preconditions: ["The incident is re-read when the command runs."],
			effects: ["Raises the rung and defers another attempt, or reports why escalation stopped."],
			result: "Whether the rung advanced, its current value, and the app-owned stop reason.",
		},
		inputs: { incident_id: "The incident whose current state controls escalation." },
		outputs: {
			escalated: "Whether this attempt raised the rung.",
			rung: "The current escalation rung.",
			reason: "The app-owned result reason.",
		},
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : EscalateIncidentTypes.Input, output : EscalateIncidentTypes.Result }, Str)
	example = |_| {
		incident_id = Ref.from_str("inc_0000000000e008000000000000").map_err(|_| "invalid example reference")?
		Ok({
			input: { incident_id },
			output: { escalated: Bool.False, rung: 1, reason: "acknowledged" },
		})
	}

	verify_input : Str, U64 -> Try(EscalateIncidentTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		incident = Data.snapshot(snapshot)?.incidents.first().map_err(|_| "seed an incident before checking escalation")?
		Ok({ incident_id: incident.id })
	}

	verify_result : Str, EscalateIncidentTypes.Result, Str -> Try(Bool, Str)
	verify_result = |before, result, after| {
		old = Data.snapshot(before)?.incidents.first().map_err(|_| "original incident missing")?
		incident = Data.snapshot(after)?.incidents.find_first(|row| row.id == old.id).map_err(|_| "incident missing")?
		expected_escalated = old.value.status == "Open" and old.value.rung < 3
		expected_rung = if expected_escalated { old.value.rung + 1 } else { old.value.rung }
		expected_reason =
			if expected_escalated {
				"escalated"
			} else if old.value.status == "Acknowledged" {
				"acknowledged"
			} else if old.value.status == "Resolved" {
				"resolved"
			} else {
				"max_rung"
			}
		Ok(
			incident.value.rung == expected_rung
				and result.escalated == expected_escalated
				and result.rung == expected_rung
				and result.reason == expected_reason,
		)
	}
}
