import pf.Api
import pf.Context
import pf.Cursor
import pf.Handler
import pf.PageSize
import pf.Tx
import Commands
import Data
import Errors
import SaveRevisionTypes

SaveRevision :: [].{
	definition = Api.command({
		audience: Owners,
		handler: Handler.local(handle),
		execution: Api.current_state([Api.create(Data.revisions)]),
		contract,
		verification: { input: verify_input, check: verify_result },
	}).require_all_rows(Data.revisions)

	handle : Context, SaveRevisionTypes.Input -> Tx(SaveRevisionTypes.Output)
	handle = |context, input| {
		if input.html.trim().is_empty() or input.html.count_utf8_bytes() > 16_384 or input.html.to_utf8().contains(0) {
			return Tx.reject(Errors.invalid_html)
		}
		Tx.count(Data.all_revisions(Cursor.start, PageSize.default)).and_then(
			|count|
				Tx.create(Data.revisions, { number: count + 1, html: input.html, author: context.actor() })
					.map(|row| { id: row.value.number }),
		)
	}

	contract = {
		title: "Save a dashboard revision",
		usage: {
			purpose: "Record the supplied HTML as a new immutable revision.",
			use_when: ["Saving a draft or sharing an exact version of the dashboard."],
			avoid_when: [],
			preconditions: ["The caller is an app owner and supplies nonblank HTML without NUL characters."],
			effects: ["Appends one revision with the authenticated author."],
			result: "A positive revision number for a pinned preview link.",
		},
		inputs: { html: "Standalone HTML, up to 16,384 UTF-8 bytes." },
		outputs: { id: "The immutable revision number in this app." },
		example: |_| Ok({ input: { html: "<h1>Channel activity</h1>" }, output: { id: 1 } }),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.invalid_html],
	}

	verify_input : Str, U64 -> Try(SaveRevisionTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ html: "<p>Revision ${seed.to_str()}</p>" })

	verify_result : Str, SaveRevisionTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, output, after| {
		old = Data.verification_snapshot(before)?
		new = Data.verification_snapshot(after)?
		caller = Api.verification_context(before)?
		input : Try({ html : Str }, _)
		input = Json.parse(caller.input)
		html = input.map_err(|_| "invalid save verification input")?.html
		expected = old.live.revisions.len() + 1
		created = new.live.revisions.find_first(|row| row.value.number == expected)
			.map_err(|_| "saved revision missing")?
		Ok(
			output.id == expected and new.live.revisions.len() == expected
				and created.value.html
					== html
					and created.value.author == caller.actor and created.version.to_u64() == 1
						and old.live.revisions.all(
							|row| new.live.revisions.any(
								|other|
									other.id
										== row.id
										and other.version == row.version and other.value.number == row.value.number
											and other.value.html
												== row.value.html
												and other.value.author == row.value.author,
							),
						)
							and old.deleted.revisions.is_empty() and new.deleted.revisions.is_empty(),
		)
	}

	invalid_html = Api.error({
		description: "HTML must be nonblank, NUL-free and at most 16,384 UTF-8 bytes.",
		recovery: "Add content and save again.",
		verification: |_| Api.failed_command(Commands.save_revision, |_snapshot, _seed| Ok({ html: " " })),
	})
}
