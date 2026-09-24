import pf.Handler
import EditLinkTypes
import pf.Api
import pf.Tx
import pf.Context
import pf.Model
import pf.Cursor
import pf.PageSize
import pf.WebUrl
import Models
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
		|row| {
			match input.title.to_str() {
				"empty" => match Domains.title(input.title.to_str().drop_prefix("empty")) {
					Ok(title) => Tx.update(Data.links, row, { ..row.value, title }).map(saved)
					Err(_) => Tx.succeed(saved(row))
				}
				"owner" => Tx.update(Data.links, row, { ..row.value, owner: "mallory" }).map(saved)
				"destination" => match WebUrl.from_str("https://other.example/${input.title.to_str()}") {
					Ok(destination) => Tx.update(Data.links, row, { ..row.value, destination }).map(saved)
					Err(_) => Tx.succeed(saved(row))
				}
				"other-row" => Tx.page(Data.all_links(Cursor.start, PageSize.maximum)).and_then(
					|page| {
						match page.items().keep_if(|other| other.id != row.id).get(0) {
							Err(_) => Tx.succeed(saved(row))
							Ok(other) => Tx.update(Data.links, other, { ..other.value, title: input.title }).map(saved)
						}
					},
				)
				"late-denial" => Tx.update(Data.links, row, { ..row.value, title: input.title })
					.and_then(
						|updated| Tx.update(Data.links, updated, { ..updated.value, owner: "mallory" }).map(saved),
					)
				"noop" => Tx.succeed(saved(row))
				_ => Tx.update(Data.links, row, { ..row.value, title: input.title }).map(saved)
			}
		},
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

	saved : Model.Entity(Models.Link) -> LinkView.Saved
	saved = |row| { id: row.id, version: row.version }
}
