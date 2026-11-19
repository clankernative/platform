import Observe
import Resource
import Context

# Organization reads through a keyless service account. Every action has a fixed scope and identity; an
# application names groups and members inside its grant, never a subject, scope or URL.
GoogleWorkspace :: [].{
	# A group as the Directory reports it. `email` is the primary address, which may differ from an alias the
	# application asked about; it is always in one of the grant's grantee domains.
	Group : { id : Str, email : Str, name : Str }

	GroupOutcome : [Found(Group), NotFound]

	# Direct or nested membership. `GroupNotFound` is distinct from `NotMember`.
	MembershipOutcome : [Member, NotMember, GroupNotFound]

	group : Context, Str -> Observe(GroupOutcome)
	group = |context, group_email| Resource.bind(context, "google_workspace").and_then(
		|resource| group_with(resource, group_email),
	)

	group_with : Resource, Str -> Observe(GroupOutcome)
	group_with = |resource, group_email| Observe.capability(
		"google_workspace.group.v1",
		Json.to_str({ handle: Resource.token(resource), group_email }),
	).and_then(
		|raw| {
			parsed : Try(GroupOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_workspace_group"))
		},
	)

	group_member : Context, Str, Str -> Observe(MembershipOutcome)
	group_member = |context, group_email, member_email| Resource.bind(context, "google_workspace").and_then(
		|resource| group_member_with(resource, group_email, member_email),
	)

	group_member_with : Resource, Str, Str -> Observe(MembershipOutcome)
	group_member_with = |resource, group_email, member_email| Observe.capability(
		"google_workspace.group_member.v1",
		Json.to_str({ handle: Resource.token(resource), group_email, member_email }),
	).and_then(
		|raw| {
			parsed : Try(MembershipOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_workspace_membership"))
		},
	)
}
