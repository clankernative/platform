import pf.Handler
import EditLinkTypes
import pf.Api
import pf.Tx
import pf.Context
import LinkView
import Data
import Domains
import Selectors
import LinkScenarios

EditLink :: [].{
	definition =
		Api.command({
			handler: Handler.local(handle),
			contract,
			execution: Api.edit(
				Data.links,
				Selectors.edit_input_link_id,
				Selectors.edit_input_expected_version,
				[
					Api.update(
						Data.links,
						[
							Api.field(Selectors.links_title),
							Api.field(Selectors.links_owner),
							Api.field(Selectors.links_destination),
						],
					),
				],
			),
			verification: { input: verify_input, check: verify_result },
		})

	handle : Context, EditLinkTypes.Input -> Tx(LinkView.Saved)
	handle = |_context, input| Tx.get(Data.links, input.link_id).and_then(
		|row|
			Tx.update(Data.links, row, { ..row.value, title: input.title })
				.map(|saved| { id: saved.id, version: saved.version }),
	)

	contract =
		{
			title: "Edit a link",
			usage: {
				purpose: "Update a saved link title.",
				use_when: ["Renaming a known link."],
				avoid_when: ["Creating a new link."],
				preconditions: ["Read the current revision before editing."],
				effects: ["Updates the saved link title."],
				result: "The saved link identifier and revision.",
			},
			inputs: {
				link_id: "The link to edit.",
				expected_version: "The revision read before this edit.",
				title: "The replacement title.",
			},
			outputs: LinkView.saved_fields,
			example: example,
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
			errors: [],

		}

	example : {} -> Try({ input : EditLinkTypes.Input, output : LinkView.Saved }, Str)
	example = |_| {
		row = LinkView.example({})?
		Ok({
			input: { link_id: row.id, expected_version: row.version, title: row.title },
			output: { id: row.id, version: row.version },
		})
	}

	verify_input : Str, U64 -> Try(EditLinkTypes.Input, Str)
	verify_input = |snapshot, seed| {
		row = LinkScenarios.first(snapshot)?
		title = Domains.title("Edited ${seed.to_str()}")?
		Ok({ link_id: row.id, expected_version: row.version, title })
	}

	verify_result : Str, LinkView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?.links.find_first(|row| row.id == saved.id).map_err(|_| "missing old row")?
		row = Data.snapshot(after)?.links.find_first(|item| item.id == saved.id).map_err(|_| "missing new row")?
		Ok(
			row.version
				== saved.version
				and row.version.to_u64()
					== old.version.to_u64() + 1
					and row.value.owner
						== old.value.owner
						and row.value.destination.to_str() == old.value.destination.to_str(),
		)
	}
}
