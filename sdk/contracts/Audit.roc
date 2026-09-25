import Observe
import Cursor
import PageSize
import CollectionPage

# This application's own history, read by the application itself.
#
# The platform audit log is its owners' — the authority policy's `admins` — and
# nobody else's. An application that wants its people to see what happened reads
# its history here and serves it through an ordinary query or page; whoever that
# operation's policy grants is the audience. Nothing else widens it.
#
# Only an operation whose authority policy lists `audit.history.v1` in its
# `observations` may read, like any other observation, and the grant is rechecked
# against current authority. What comes back is this application's completed
# commands and queries and the rows they changed: never another application's,
# never the platform's admission, rejection, web or retention events, and never
# inputs, results, tokens or bodies. Row changes name the record and the fields
# that changed but carry no values, because the platform does not keep values: an
# append-only copy would outlive the deletion and retention of the rows it copied.
# Read the current row through the operation's own model grant when a value is
# wanted.
Audit :: [].{
	# One row written by an entry. `before_version` is zero when the write created
	# the row. `fields` names the fields whose value changed.
	Change : { model : Str, record_id : Str, before_version : I64, after_version : I64, fields : List(Str) }

	# One completed invocation, newest first.
	#
	# `actor` is whom it acted for and `initiator` who authenticated; they differ
	# only under an operator-approved delegation. `trigger` is `request`,
	# `schedule`, `command_request`, `ingress` or `delegated`, and may grow. `outcome`
	# is `success` or `failure`. `at` is Unix seconds on the host clock. At most 20
	# changes are listed; `change_count` is always the total, so a shortened list
	# is visible as one. `sequence` orders entries and is stable; larger is newer.
	Entry : {
		sequence : I64,
		operation : Str,
		actor : Str,
		initiator : Str,
		trigger : Str,
		outcome : Str,
		at : I64,
		changes : List(Change),
		change_count : U64,
	}

	# `operations` names the full operation names to include, such as
	# `links.edit`; empty includes every operation, queries among them. Names are
	# matched rather than checked, so a retired operation's history stays
	# readable. Up to 64 names. `limit` is at most 50; a page may hold fewer and
	# still continue. `after` is the previous page's `next_after`, bound to the
	# same actor, operation and names, and expires after 24 hours.
	Request : { operations : List(Str), after : Cursor, limit : PageSize }

	history : Request -> Observe(CollectionPage(Entry))
	history = |request| Observe.capability(
		"audit.history.v1",
		Json.to_str({
			operations: request.operations,
			after: Cursor.to_str(request.after),
			limit: PageSize.to_i64(request.limit),
		}),
	).and_then(|raw| Observe.from_host(decode(raw)))

	decode : Str -> Try(CollectionPage(Entry), Str)
	decode = |raw| {
		parsed : Try({ items : List(Entry), has_more : Bool, next_after : Str }, _)
		parsed = Json.parse(raw)
		page = parsed.map_err(|_| "invalid_audit_history")?
		next = Cursor.from_str(page.next_after).map_err(|_| "invalid_audit_history")?
		CollectionPage.from_parts(page.items, page.has_more, next)
	}
}
