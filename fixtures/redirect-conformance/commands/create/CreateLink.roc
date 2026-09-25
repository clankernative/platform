import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import CreateLinkTypes
import LinkNames
import LinkView
import Data
import Errors

# Stores any nonempty destination unchecked, so the redirect tests can prove that
# the host, not the application, refuses a destination it must not follow.
CreateLink :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.links)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, CreateLinkTypes.Input -> Tx(LinkView.Saved)
	handle = |_context, input| if LinkNames.valid(input.name) and !input.url.is_empty() {
		Tx.create(Data.links, { name: input.name, url: input.url, visits: 0, deleted: Bool.False })
			.map(|row| { id: row.id, name: row.value.name })
	} else {
		Tx.reject(Errors.invalid_link)
	}

	contract = {
		title: "Create a link",
		usage: {
			purpose: "Save a named destination, or a wildcard whose last name segment is %s.",
			use_when: ["Adding a go link."],
			avoid_when: ["Following a link; that is the visit command."],
			preconditions: [],
			effects: ["Creates one link with no visits."],
			result: "The saved link identifier and name.",
		},
		inputs: { name: "Lowercase slash-separated name, optionally ending in /%s.", url: "The destination." },
		outputs: LinkView.saved_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.invalid_link],
	}

	example : {} -> Try({ input : CreateLinkTypes.Input, output : LinkView.Saved }, Str)
	example = |_| {
		row = LinkView.example({})?
		Ok({ input: { name: row.name, url: row.url }, output: { id: row.id, name: row.name } })
	}

	verify_input : Str, U64 -> Try(CreateLinkTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ name: "generated-${seed.to_str()}", url: "https://example.com/" })

	verify_result : Str, LinkView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.links.len()
				== old.links.len() + 1
				and next.links.any(|row| row.id == saved.id and row.value.name == saved.name and row.value.visits == 0),
		)
	}
}
