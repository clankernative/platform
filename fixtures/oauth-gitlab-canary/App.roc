import ProjectsConnection
import InspectIntent
import CanaryInvariants

App :: [].{
	definition = {
		namespace: "oauthgitlab",
		connections: { projects: ProjectsConnection.requirement },
		operations: { inspect: InspectIntent.definition },
		pages: {},
		properties: { entries: CanaryInvariants.entries },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "" },
	}
}
