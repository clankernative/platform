import OpenIncidentTypes
import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import pf.Ref
import pf.RowVersion
import Data
import Commands

OpenIncident :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.incidents), Api.defer(Commands.escalate)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, OpenIncidentTypes.Input -> Tx(OpenIncidentTypes.Saved)
	handle = |_context, input|
		Tx.create(Data.incidents, { title: input.title, status: "Open", rung: 0 })
			.and_then(|incident|
				Commands.escalate
					.defer_for(Data.incidents, incident, { incident_id: incident.id }, 300.I64)
					.map(|_| { id: incident.id, version: incident.version }),
			)

	contract = {
		errors: [],
		title: "Open an incident",
		usage: {
			purpose: "Record an open incident and arrange its first escalation attempt.",
			use_when: ["A responder reports a new incident."],
			avoid_when: ["Acknowledging or resolving an existing incident."],
			preconditions: [],
			effects: ["Creates an Open incident and defers escalation for 300 seconds."],
			result: "The incident identifier and committed revision.",
		},
		inputs: { title: "A concise incident title." },
		outputs: { id: "The incident identifier.", version: "The committed incident revision." },
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : OpenIncidentTypes.Input, output : OpenIncidentTypes.Saved }, Str)
	example = |_| {
		id = Ref.from_str("inc_0000000000e008000000000000").map_err(|_| "invalid example reference")?
		Ok({ input: { title: "Example incident" }, output: { id, version: RowVersion.one } })
	}

	verify_input : Str, U64 -> Try(OpenIncidentTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ title: "Generated incident ${seed.to_str()}" })

	verify_result : Str, OpenIncidentTypes.Saved, Str -> Try(Bool, Str)
	verify_result = |_before, saved, after| {
		incident =
			Data.snapshot(after)?
				.incidents
				.find_first(|row| row.id == saved.id)
				.map_err(|_| "created incident missing")?
		Ok(incident.version == saved.version and incident.value.status == "Open" and incident.value.rung == 0)
	}
}
