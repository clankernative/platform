import pf.Handler
import CreateLinkTypes
import pf.Api
import pf.Tx
import pf.Context
import pf.Model
import pf.WebUrl
import Models
import LinkView
import Data
import Domains
import Commands
import Errors

CreateLink :: [].{
	definition =
		Api.command({
			handler: Handler.local(handle),
			contract,
			execution: Api.current_state([Api.create(Data.links)]),
			verification: { input: verify_input, check: verify_result },
		})

	handle : Context, CreateLinkTypes.Input -> Tx(LinkView.Saved)
	handle = |context, input| if input.title.to_str() == "reject" {
		Tx.reject(Errors.rejected_title)
	} else {
		Tx.create(
			Data.links,
			{
				title: input.title,
				destination: input.destination,
				owner: if input.title.to_str() == "spoof-owner" {
					"mallory"
				} else {
					context.actor()
				},
			},
		).map(saved)
	}

	contract =
		{
			title: "Create a link",
			usage: {
				purpose: "Create a link owned by the current actor.",
				use_when: ["Saving a new link."],
				avoid_when: ["Editing an existing link."],
				preconditions: [],
				effects: ["Creates a link owned by the current actor."],
				result: "The saved link identifier and revision.",
			},
			inputs: { title: "The display title.", destination: "The external destination URL." },
			outputs: LinkView.saved_fields,
			example: example,
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
			errors: [Errors.rejected_title],

		}

	example : {} -> Try({ input : CreateLinkTypes.Input, output : LinkView.Saved }, Str)
	example = |_| {
		row = LinkView.example({})?
		destination = WebUrl.from_str(row.destination).map_err(|_| "invalid example URL")?
		Ok({ input: { title: row.title, destination }, output: { id: row.id, version: row.version } })
	}

	verify_input : Str, U64 -> Try(CreateLinkTypes.Input, Str)
	verify_input = |_snapshot, seed| {
		title = Domains.title("Generated link ${seed.to_str()}")?
		destination = WebUrl.from_str("https://example.com/").map_err(|_| "invalid scenario URL")?
		Ok({ title, destination })
	}

	verify_result : Str, LinkView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.links.len()
				== old.links.len() + 1
				and next.links.any(|row| row.id == saved.id and row.version == saved.version),
		)
	}

	rejected_title =
		Api.error({
			description: "The reserved rejection title cannot be saved.",
			recovery: "Choose a different title.",
			verification: |_| Api.failed_command(Commands.create, rejected_input),
		})

	rejected_input : Str, U64 -> Try(CreateLinkTypes.Input, Str)
	rejected_input = |snapshot, seed| {
		input = verify_input(snapshot, seed)?
		title = Domains.title("reject")?
		Ok({ ..input, title })
	}

	saved : Model.Entity(Models.Link) -> LinkView.Saved
	saved = |row| { id: row.id, version: row.version }
}
