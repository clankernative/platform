import pf.Api
import pf.Handler
import pf.Context
import pf.Model
import pf.Selection
import pf.Tx
import VisitLinkTypes
import LinkNames
import LinkView
import Models
import Data
import Selectors
import Errors

# Resolve an exact active name first, otherwise the active wildcard for all but the
# last segment; count the visit and return the destination. The redirect routes in
# pages/Redirects.roc bind this command, as GoLinks binds golinks.visit.
VisitLink :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.update(Data.links, [Api.field(Selectors.links_visits)])]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, VisitLinkTypes.Input -> Tx(LinkView.Visit)
	handle = |_context, input| find(input.path).and_then(
		|found| match found {
			Some(row) if !row.value.deleted => record(row, row.value.url)
			_ => wildcard(input.path)
		},
	)

	contract = {
		title: "Follow a link",
		usage: {
			purpose: "Resolve a path to a destination and count the visit.",
			use_when: ["Following a go link."],
			avoid_when: ["Reading a link without counting a visit."],
			preconditions: [],
			effects: ["Increments the resolved link's visit count."],
			result: "The destination and the new visit count.",
		},
		inputs: { path: "The requested path, decoded, without its leading slash." },
		outputs: LinkView.visit_fields,
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.missing_link],
	}

	example : {} -> Try({ input : VisitLinkTypes.Input, output : LinkView.Visit }, Str)
	example = |_| {
		row = LinkView.example({})?
		Ok({ input: { path: row.name }, output: { id: row.id, url: row.url, visits: 1 } })
	}

	verify_input : Str, U64 -> Try(VisitLinkTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		state = Data.snapshot(snapshot)?
		row = state.links.find_first(|item| !item.value.deleted and item.value.name.split_on("%s").len() == 1)
			.map_err(|_| "seed an active exact link first")?
		Ok({ path: row.value.name })
	}

	verify_result : Str, LinkView.Visit, Str -> Try(Bool, Str)
	verify_result = |before, visit, after| {
		old = Data.snapshot(before)?.links.find_first(|row| row.id == visit.id).map_err(|_| "visited link missing")?
		saved = Data.snapshot(after)?.links.find_first(|row| row.id == visit.id).map_err(|_| "visited link missing")?
		Ok(saved.value.visits == old.value.visits + 1 and visit.visits == saved.value.visits and !old.value.deleted)
	}

	find : Str -> Tx([Some(Model.Entity(Models.Link)), None])
	find = |name| Tx.find(Selection.filter(Data.links, Data.links_name_equal(name)))

	wildcard : Str -> Tx(LinkView.Visit)
	wildcard = |path| match LinkNames.wildcard(path) {
		None => Tx.reject(Errors.missing_link)
		Some(candidate) => find(candidate.name).and_then(
			|found| match found {
				Some(row) if !row.value.deleted => record(row, LinkNames.interpolate(row.value.url, candidate.capture))
				_ => Tx.reject(Errors.missing_link)
			},
		)
	}

	record : Model.Entity(Models.Link), Str -> Tx(LinkView.Visit)
	record = |row, url| Tx.update(Data.links, row, { ..row.value, visits: row.value.visits + 1 })
		.map(|saved| { id: saved.id, url, visits: saved.value.visits })
}
