import pf.Api
import pf.Handler
import pf.Context
import pf.Query
import pf.Cursor
import pf.PageSize
import ListLinksTypes

DirectoryUnavailable :: [].{
	View : { limit : I64 }

	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	# Reads no links, so it can still answer when the directory's own read fails.
	handle : Context, ListLinksTypes.Input -> Query(View)
	handle = |_context, input| Query.succeed({ limit: input.limit.to_i64() })

	contract = {
		title: "Explain that the directory is unavailable",
		usage: {
			purpose: "Present an app-owned page when the link directory cannot be served.",
			use_when: ["The directory page failed on the server."],
			avoid_when: ["Listing or following links."],
			preconditions: [],
			effects: [],
			result: "The requested page length, without reading links.",
		},
		inputs: { after: "Continuation cursor from the directory route.", limit: "The requested page length." },
		outputs: { limit: "The page length the directory will show once it is available." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : ListLinksTypes.Input, output : View }, Str)
	example = |_| Ok({ input: { after: Cursor.start, limit: PageSize.default }, output: { limit: 20 } })

	verify_input : Str, U64 -> Try(ListLinksTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ after: Cursor.start, limit: PageSize.default })

	verify_result : Str, View, Str -> Try(Bool, Str)
	verify_result = |before, output, after| Ok(before == after and output.limit == 20)
}
