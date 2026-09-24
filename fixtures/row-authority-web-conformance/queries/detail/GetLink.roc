import pf.Handler
import GetLinkTypes
import pf.Api
import pf.Query
import pf.Context
import LinkView
import Data
import LinkScenarios

GetLink :: [].{
	definition =
		Api.query(
			{ handler: Handler.local(handle), contract, verification: { input: verify_input, check: verify_result } },
		)

	handle : Context, GetLinkTypes.Input -> Query(LinkView.Value)
	handle = |_context, input| Query.get(Data.links, input.link_id).map(LinkView.from_row)

	contract =
		{
			title: "Get a link",
			usage: {
				purpose: "Retrieve a link and its current revision.",
				use_when: ["Inspecting a known link or preparing an edit."],
				avoid_when: ["Discovering link identifiers."],
				preconditions: [],
				effects: [],
				result: "The current link data and revision.",
			},
			inputs: { link_id: "The link to retrieve." },
			outputs: LinkView.fields,
			example: example,
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
			errors: [],

		}

	example : {} -> Try({ input : GetLinkTypes.Input, output : LinkView.Value }, Str)
	example = |_| {
		row = LinkView.example({})?
		Ok({ input: { link_id: row.id }, output: row })
	}

	verify_input : Str, U64 -> Try(GetLinkTypes.Input, Str)
	verify_input = |snapshot, _seed| Ok({ link_id: LinkScenarios.first(snapshot)?.id })

	verify_result : Str, LinkView.Value, Str -> Try(Bool, Str)
	verify_result = |before, view, after| {
		row = Data.snapshot(before)?.links.find_first(|item| item.id == view.id).map_err(|_| "missing row")?
		Ok(before == after and row.version == view.version and row.value.title.to_str() == view.title.to_str())
	}
}
