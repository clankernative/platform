import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Query
import Errors
import Data
import NotificationAccess
import Publications
import GetPublicationTypes

GetPublication :: [].{
	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})
			.require_all_rows(Data.publications)

	prepare : Context, GetPublicationTypes.Input -> Observe(Bool)
	prepare = |_context, input| NotificationAccess.check(input.app_id)

	handle : Context, GetPublicationTypes.Input, Bool -> Query(Publications.Output)
	handle = |_context, input, allowed| {
		if !allowed {
			return Query.from_try(Err(Errors.publication_denied))
		}
		Query.find(Publications.find(input.app_id, input.publication_id)).and_then(
			|found| match found {
				None => Query.from_try(Err(Errors.invalid_publication))
				Some(row) => Query.succeed(Publications.output(row, Bool.True))
			},
		)
	}

	contract = {
		title: "Inspect an accepted notification",
		usage: {
			purpose: "Read the retained acceptance receipt after checking current app ownership.",
			use_when: [
				"Checking whether a publication identity already exists or inspecting confirmed Slack acceptance.",
			],
			avoid_when: ["Treating absent confirmation as proof a message was not posted."],
			preconditions: [
				"Current direct app ownership; original command status has independent host authorization.",
			],
			effects: [],
			result: "The retained receipt and original command status URL; message and payload are not disclosed.",
		},
		inputs: { app_id: "Business app identifier.", publication_id: "Original stable publication identity." },
		outputs: Publications.output_fields,
		example: |
			_,
		|
			Ok({
				input: { app_id: "demo", publication_id: "build-1" },
				output: { ..Publications.example({})?, duplicate: Bool.True },
			}),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.publication_denied, Errors.invalid_publication],
	}

	verify_input : Str, U64 -> Try(GetPublicationTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row = Data.snapshot(snapshot)?.publications.first().map_err(|_| "publish an event first")?
		Ok({ app_id: row.value.app_id, publication_id: row.value.publication_id })
	}

	verify_result : Str, Publications.Output, Str -> Try(Bool, Str)
	verify_result = |before, _output, after| Ok(before == after)
}
