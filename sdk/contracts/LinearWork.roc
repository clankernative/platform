import Observe
import Effects
import Resource
import Api

# Linear work tracking: reading the issues a grant points at, and moving who owns
# one. The activated resource fixes the view or label, so an application reads the
# queue it was granted and cannot name another.
#
# Deliberately separate from `Linear`, which holds identity authority — inviting
# people and suspending their accounts. A compliance queue has no business
# suspending anyone, and one contract covering both would hand it that power in
# order to let it read a list.
LinearWork :: [].{
	# Only the write. An execution contract declares external *effects*, and the
	# host refuses any handle here that is not a write capability — reads are
	# authorized by the grant's actions instead, not by being named in a contract.
	reassign_effect = Api.external("linear_work.reassign.v1")

	# A person who can own work.
	Member : { id : Str, name : Str, email : Str }

	# One tracked issue, as the workspace reports it.
	#
	# `due_date` is empty when the issue carries no due date, and that emptiness is
	# a compliance fact rather than a missing field: an issue with no due date is
	# precisely what one of the policies looks for.
	Issue : {
		id : Str,
		identifier : Str,
		title : Str,
		url : Str,
		due_date : Str,
		# Days from the Unix epoch, or -1 when the issue carries no due date.
		#
		# A day number rather than an instant, because that is what Linear means:
		# an issue is due *on a day*, with no time and no zone. Converting it to an
		# instant would invent a midnight somewhere and make "due today" depend on
		# which zone did the inventing.
		due_date_days : I64,
		priority : I64,
		priority_label : Str,
		# Milliseconds from the Unix epoch. Parsed by the host, which is where a
		# timestamp format belongs: a date library's idea of ISO-8601 is not
		# necessarily the provider's, and a silently-zero instant would make every
		# issue look decades stale.
		created_at_ms : I64,
		updated_at_ms : I64,
		state_name : Str,
		state_type : Str,
		assignee : Member,
		parent_owner : Member,
		project_owner : Member,
		team_key : Str,
		team_name : Str,
		labels : List(Str),
		attachment_urls : List(Str),
	}

	# One page of issues, and where the next one starts.
	#
	# A page rather than the whole queue, and that is the contract rather than a
	# limitation. Following every cursor inside one invocation makes the invocation
	# itself unbounded — it cannot be budgeted, retried or observed — so a caller
	# that needs the complete queue ingests it a page at a time on a schedule and
	# reads the result from its own rows, which is durable and resumable.
	#
	# `next_cursor` is meaningful only while `has_more` is true.
	Page : { issues : List(Issue), has_more : Bool, next_cursor : Str }

	# One page of the issues this grant's view or label holds.
	#
	# Pass an empty cursor for the first page.
	issues : Resource, Str -> Observe(Page)
	issues = |resource, after| Observe.capability(
		"linear_work.issues.v1",
		Json.to_str({ handle: Resource.token(resource), after }),
	).and_then(
		|raw| {
			parsed : Try(Page, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_linear_issues"))
		},
	)

	Comment : { body : Str, occurred_at : Str, actor : Str }

	Change : {
		occurred_at : Str,
		actor : Str,
		from_state : Str,
		to_state : Str,
		from_assignee : Str,
		to_assignee : Str,
		from_due_date : Str,
		to_due_date : Str,
		# Zero when the entry is not a priority change. Linear reports priority as
		# a whole number on an issue and as a decimal in history; both arrive here
		# as the same integer.
		from_priority : I64,
		to_priority : I64,
	}

	Detail : { description : Str, comments : List(Comment), history : List(Change) }

	# One issue's description and recent activity.
	issue_detail : Resource, Str -> Observe(Detail)
	issue_detail = |resource, issue_id| Observe.capability(
		"linear_work.issue_detail.v1",
		Json.to_str({ handle: Resource.token(resource), issue_id }),
	).and_then(
		|raw| {
			parsed : Try(Detail, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_linear_detail"))
		},
	)

	Assignees : { team_name : Str, current_assignee_id : Str, members : List(Member) }

	# Who may own this issue, and who owns it now.
	#
	# Disabled members are not offered: a reassignment to one is refused by the
	# provider, so presenting it as a candidate only produces a failure later.
	assignable_users : Resource, Str -> Observe(Assignees)
	assignable_users = |resource, issue_id| Observe.capability(
		"linear_work.assignable_users.v1",
		Json.to_str({ handle: Resource.token(resource), issue_id }),
	).and_then(
		|raw| {
			parsed : Try(Assignees, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_linear_assignees"))
		},
	)

	Reassignment : { assignee : Member }

	# Move ownership of one issue.
	#
	# An empty `assignee_id` clears the owner. That is a real operation and not a
	# missing argument: clearing an assignee and leaving one in place are different
	# outcomes, so the empty string is sent to the provider as an explicit null
	# rather than omitted.
	#
	# A write, and one whose retry is not safe on its own: reassignment does not
	# commute with a later human reassignment, so a caller reconciling a lost
	# acknowledgement must check the current owner rather than simply sending it
	# again.
	reassign : Resource, Str, Str -> Effects(Reassignment)
	reassign = |resource, issue_id, assignee_id| Effects.capability(
		"linear_work.reassign.v1",
		Json.to_str({ handle: Resource.token(resource), issue_id, assignee_id }),
	).and_then(
		|raw| {
			parsed : Try(Reassignment, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_linear_reassignment"))
		},
	)
}
