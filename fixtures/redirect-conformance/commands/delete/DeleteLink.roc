import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import DeleteLinkTypes
import LinkView
import Data
import Selectors

# Soft deletion: the name stays reserved, and visiting it no longer resolves.
DeleteLink :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.update(Data.links, [Api.field(Selectors.links_deleted)])]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, DeleteLinkTypes.Input -> Tx(LinkView.Saved)
	handle = |_context, input| Tx.get(Data.links, input.link_id).and_then(
		|row| Tx.update(Data.links, row, { ..row.value, deleted: Bool.True })
			.map(|saved| { id: saved.id, name: saved.value.name }),
	)

	contract = {
		title: "Delete a link",
		usage: {
			purpose: "Stop a link from resolving while keeping its name reserved.",
			use_when: ["Retiring a go link."],
			avoid_when: ["Changing a destination."],
			preconditions: [],
			effects: ["Marks one link deleted."],
			result: "The deleted link identifier and name.",
		},
		inputs: { link_id: "The link to delete." },
		outputs: LinkView.saved_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : DeleteLinkTypes.Input, output : LinkView.Saved }, Str)
	example = |_| {
		row = LinkView.example({})?
		Ok({ input: { link_id: row.id }, output: { id: row.id, name: row.name } })
	}

	verify_input : Str, U64 -> Try(DeleteLinkTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		row = Data.snapshot(snapshot)?.links.first().map_err(|_| "seed a link first")?
		Ok({ link_id: row.id })
	}

	verify_result : Str, LinkView.Saved, Str -> Try(Bool, Str)
	verify_result = |_before, saved, after| {
		row = Data.snapshot(after)?.links.find_first(|item| item.id == saved.id).map_err(|_| "deleted link missing")?
		Ok(row.value.deleted)
	}
}
