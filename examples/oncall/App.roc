import OpenIncident
import AcknowledgeIncident
import EscalateIncident
import IncidentInvariants
import Demo

App :: [].{
	definition = {
		namespace: "oncall",
		operations: {
			open: OpenIncident.definition,
			acknowledge: AcknowledgeIncident.definition,
			escalate: EscalateIncident.definition,
		},
		pages: {},
		properties: { incidents: IncidentInvariants.incidents },
		errors: {},
		examples: [Demo.definition],
		presentation: { stylesheet: "", script: "" },
	}
}
