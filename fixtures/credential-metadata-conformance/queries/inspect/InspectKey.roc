import pf.Api
import pf.Handler
import pf.Credential
import pf.Query
import pf.Observe
import pf.Context
import Credentials
import KeyFamilies
import InspectKeyTypes

InspectKey :: [].{
	Output : { status : Str, lineage : Str, version : Str, revision : U64, state : Str }

	definition = Api.query({
		handler: Handler.prepared(prepare, |_context, _input, output| Query.from_try(Ok(output))),
		contract: {
			title: "Inspect one client credential",
			usage: {
				purpose: "Read safe metadata and a stale-able management precondition.",
				use_when: ["Inspecting a listed credential."],
				avoid_when: [],
				preconditions: [],
				effects: [],
				result: "Visible metadata or a closed inspection failure.",
			},
			inputs: { lineage: "Family-specific public reference." },
			outputs: {
				status: "ok or the closed inspection failure.",
				lineage: "Visible lineage reference.",
				version: "Current version audit identity.",
				revision: "Management revision, never authorization.",
				state: "Lifecycle state.",
			},
			example: |_| Ok({ input: { lineage: "" }, output: empty("not_visible") }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({ lineage: "" }),
			check: |before, output, after| Ok(before == after and output.status == "not_visible"),
		},
	}).credentials(Credential.metadata_access(KeyFamilies.clients))

	empty : Str -> Output
	empty = |status| { status, lineage: "", version: "", revision: 0, state: "" }

	prepare : Context, InspectKeyTypes.Input -> Observe(Output)
	prepare = |_context, input| {
		lineage = match (Credentials.clients.ref_from_str)(input.lineage) {
			Ok(value) => value
			Err(_) => return Observe.value(empty("not_visible"))
		}
		(Credentials.clients.inspect)({
			lineage: lineage,
		}).map(
			|result| match result {
				Err(problem) => empty(
					match problem {
						NotVisible => "not_visible"
						Unavailable => "unavailable"
						Throttled => "throttled"
					},
				)
				Ok(value) => {
					status: "ok",
					lineage: value.summary.lineage.to_str(),
					version: value.summary.current_version.id(),
					revision: match value.rotation {
						None => 0
						Some(snapshot) => snapshot.revision()
					},
					state: match value.summary.state {
						Active => "active"
						Rotating => "rotating"
						Revoked => "revoked"
					},
				}
			},
		)
	}
}
