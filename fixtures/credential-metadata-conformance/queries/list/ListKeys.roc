import pf.Api
import pf.Handler
import pf.Credential
import pf.PageSize
import pf.Query
import pf.Observe
import pf.Context
import pf.CollectionPage
import Credentials
import KeyFamilies
import ListKeysTypes
import Data

ListKeys :: [].{
	Item : { lineage : Str, version : Str, principal : Str, label : Str, state : Str, grant : Str, expires_at : I64 }

	Output : { status : Str, page : CollectionPage(Item) }

	definition = Api.query({
		handler: Handler.prepared(prepare, |_context, _input, output| Query.from_try(Ok(output))),
		contract: {
			title: "List client credential metadata",
			usage: {
				purpose: "Read one bounded page visible to the inherited principal.",
				use_when: ["Credential management."],
				avoid_when: [],
				preconditions: [],
				effects: [],
				result: "Safe metadata or a closed read failure.",
			},
			inputs: {
				after: "Empty starts traversal; otherwise use next_after unchanged.",
				limit: "Page size from one through 100.",
			},
			outputs: {
				status: "ok or the closed list failure.",
				page: {
					description: "Visible credential lineages.",
					fields: {
						items: {
							description: "Safe metadata rows.",
							each: {
								lineage: "Family reference.",
								version: "Current version audit identity.",
								principal: "Credential principal.",
								label: "Safe label.",
								state: "Lifecycle state.",
								grant: "Grant digest.",
								expires_at: "Unix expiry seconds.",
							},
						},
						has_more: "Another bounded page is available.",
						next_after: "Family-specific continuation.",
					},
				},
			},
			example: |_| Ok({ input: { after: "", limit: 2 }, output: empty("ok") }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		verification: {
			input: |_snapshot, _seed| Ok({ after: "", limit: 2 }),
			check: |before, output, after| {
				state = Data.snapshot(before)?
				clients = state.entries.keep_if(|row| row.value.note.starts_with("cr1_clients_"))
				items = output.page.items()
				Ok(
					before == after and output.status == "ok"
						and items.len() == U64.min(clients.len(), 2)
							and output.page.has_more() == (clients.len() > 2)
								and items
									.all(
										|
											item,
										| clients.any(|row| row.value.note == item.lineage) and item.state == "active",
									),
				)
			},
		},
	}).credentials(Credential.metadata_access(KeyFamilies.clients))

	empty : Str -> Output
	empty = |status| { status, page: CollectionPage.empty }

	prepare : Context, ListKeysTypes.Input -> Observe(Output)
	prepare = |_context, input| {
		after = match (Credentials.clients.cursor_from_str)(input.after) {
			Ok(value) => value
			Err(_) => return Observe.value(empty("invalid_cursor"))
		}
		limit = match PageSize.from_i64(input.limit) {
			Ok(value) => value
			Err(_) => return Observe.value(empty("invalid_cursor"))
		}
		(Credentials.clients.list)({ after, limit }).map(
			|result| match result {
				Err(problem) => empty(
					match problem {
						Denied => "denied"
						InvalidCursor => "invalid_cursor"
						Unavailable => "unavailable"
						Throttled => "throttled"
					},
				)
				Ok(page) => {
					status: "ok",
					page: page.map(
						|item| {
							lineage: item.lineage.to_str(),
							version: item.current_version.id(),
							principal: item.principal,
							label: match item.label {
								None => ""
								Some(value) => value
							},
							state: match item.state {
								Active => "active"
								Rotating => "rotating"
								Revoked => "revoked"
							},
							grant: item.grant,
							expires_at: item.expires_at,
						},
					),
				}
			},
		)
	}
}
