import AcknowledgeIncidentTypes
import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.Ref
import pf.RowVersion
import Data
import Selectors

AcknowledgeIncident :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.edit(
			Data.incidents,
			Selectors.acknowledge_input_incident_id,
			Selectors.acknowledge_input_expected_version,
			[Api.update(Data.incidents, [Api.field(Selectors.incidents_status)])],
		),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, AcknowledgeIncidentTypes.Input -> Tx(AcknowledgeIncidentTypes.Saved)
	handle = |_context, input|
		Tx.get(Data.incidents, input.incident_id)
			.and_then(|incident|
				Tx.update(Data.incidents, incident, { ..incident.value, status: "Acknowledged" })
					.map(|changed| { id: changed.id, version: changed.version }),
			)

	contract = {
		errors: [],
		title: "Acknowledge an incident",
		usage: {
			purpose: "Mark an incident as acknowledged using the revision the responder reviewed.",
			use_when: ["A responder takes ownership of an open incident."],
			avoid_when: ["Opening or resolving an incident."],
			preconditions: ["The incident revision must still match the supplied version."],
			effects: ["Changes the incident status to Acknowledged."],
			result: "The incident identifier and committed revision.",
		},
		inputs: { incident_id: "The incident to acknowledge.", expected_version: "The incident revision read by the responder." },
		outputs: { id: "The incident identifier.", version: "The committed incident revision." },
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : AcknowledgeIncidentTypes.Input, output : AcknowledgeIncidentTypes.Saved }, Str)
	example = |_| {
		incident_id = Ref.from_str("inc_0000000000e008000000000000").map_err(|_| "invalid example reference")?
		Ok({
			input: { incident_id, expected_version: RowVersion.one },
			output: { id: incident_id, version: RowVersion.from_u64(2).map_err(|_| "invalid example version")? },
		})
	}

	verify_input : Str, U64 -> Try(AcknowledgeIncidentTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		incident = Data.snapshot(snapshot)?.incidents.find_first(|row| row.value.status == "Open").map_err(|_| "open incident missing")?
		Ok({ incident_id: incident.id, expected_version: incident.version })
	}

	verify_result : Str, AcknowledgeIncidentTypes.Saved, Str -> Try(Bool, Str)
	verify_result = |_before, saved, after| {
		incident = Data.snapshot(after)?.incidents.find_first(|row| row.id == saved.id).map_err(|_| "acknowledged incident missing")?
		Ok(incident.version == saved.version and incident.value.status == "Acknowledged")
	}
}
