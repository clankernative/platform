import pf.Api
import pf.Context
import pf.Handler
import pf.Observe
import pf.Query
import pf.WorkspaceDirectory
import DirectoryUserTypes

# Public-SDK reachability probe. The native provider world, not this fixture,
# supplies the path; no app row or employee profile is manufactured.
DirectoryUser :: [].{
	definition = Api.query({
		handler: Handler.prepared(prepare, handle),
		contract,
		verification: { input: |_snapshot, _seed| Ok({}), check: verify_result },
	}).observes("workspace_directory.user_path.v1")

	prepare : Context, DirectoryUserTypes.Input -> Observe(WorkspaceDirectory.UserPath)
	prepare = |context, _input| WorkspaceDirectory.user_path(context)

	handle : Context, DirectoryUserTypes.Input, WorkspaceDirectory.UserPath -> Query(WorkspaceDirectory.UserPath)
	handle = |_context, _input, fact| Query.succeed(fact)

	contract = {
		title: "Observe the current Directory user path",
		usage: {
			purpose: "Qualify the public SDK's independent current-actor path observation through an admitted native query.",
			use_when: ["Native conformance tests use an owned synthetic provider and current host authority."],
			avoid_when: ["Inferring primary email, membership from a hierarchy, or providing another actor as input."],
			preconditions: [
				"The host independently binds current actor, customer and connection to the Directory resource; this query supplies no authority.",
			],
			effects: [],
			result: "The native customer-bound user-path fact, without a hierarchy read or application mutation.",
		},
		inputs: {},
		outputs: {
			actor: "Host-bound current actor, not a claimed primary email.",
			customer_id: "Resource-bound customer validated against the provider response.",
			user_path: "Checked provider path, never a default on failure.",
			captured_at: "Invocation time supplied by the native host.",
		},
		example: |
			_,
		|
			Ok({
				input: {},
				output: {
					actor: "fixture@example.test",
					customer_id: "synthetic-customer-1",
					user_path: "/Example",
					captured_at: 100,
				},
			}),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	verify_result : Str, WorkspaceDirectory.UserPath, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		caller = Api.verification_context(before)?
		Ok(
			before == after and output.actor == caller.actor and !output.customer_id.is_empty()
				and output.user_path.starts_with("/") and output.captured_at >= 0,
		)
	}
}
