import pf.Api
import pf.Handler
import pf.Query
import pf.Context
import ProjectsConnection
import InspectIntentTypes

InspectIntent :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract: {
			title: "GitLab canary intent",
			usage: {
				purpose: "Inspect the GitLab requirement selected for installation qualification.",
				use_when: ["Reviewing the canary's declared account access."],
				avoid_when: ["Checking live readiness or listing provider projects."],
				preconditions: [],
				effects: [],
				result: "The registered connection name and its app-owned purpose.",
			},
			inputs: {},
			outputs: { connection: "Registered connection name.", usage: "App-owned access purpose." },
			example: |_| Ok({ input: {}, output: intent({}) }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({}),
			check: |before, output, after| Ok(before == after and output == intent({})),
		},
	})

	handle : Context, InspectIntentTypes.Input -> Query(InspectIntentTypes.Output)
	handle = |_context, _input| Query.from_try(Ok(intent({})))

	intent : {} -> InspectIntentTypes.Output
	intent = |_| { connection: "projects", usage: ProjectsConnection.requirement.metadata().usage }
}
