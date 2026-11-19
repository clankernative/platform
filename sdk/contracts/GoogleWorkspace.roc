import Observe
import Resource
import Context

# Organization reads through a keyless service account: Directory reads as the account itself, Calendar
# reads by domain-wide delegation as the grant's Calendar reader. Every action has a fixed scope and
# identity; an application names groups, members, calendars and events inside its grant, never a subject,
# scope or URL.
GoogleWorkspace :: [].{
	# A group as the Directory reports it. `email` is the primary address, which may differ from an alias the
	# application asked about; it is always in one of the grant's grantee domains.
	Group : { id : Str, email : Str, name : Str }

	GroupOutcome : [Found(Group), NotFound]

	# Direct or nested membership. `GroupNotFound` is distinct from `NotMember`.
	MembershipOutcome : [Member, NotMember, GroupNotFound]

	OptionalText : [Some(Str), None]

	# The role a calendar's ACL gives one group. `None` means the ACL names no role for it.
	GroupRole : [None, FreeBusyReader, Reader, Writer, Owner]

	Calendar : { id : Str, summary : Str, group_role : GroupRole }

	# A calendar the grant's Calendar reader cannot see is `NotFound`, as Google answers it.
	CalendarOutcome : [Found(Calendar), NotFound]

	EventStatus : [Confirmed, Tentative, Cancelled]

	Visibility : [Default, Public, Private, Confidential]

	# Times are RFC 3339 with an offset, as Google reports them. `start` and `end` are `None` only on a
	# cancelled event, which Google may report by id alone. `meeting_code` is a Meet `xxx-xxxx-xxx` code.
	Event : {
		id : Str,
		status : EventStatus,
		visibility : Visibility,
		start : OptionalText,
		end : OptionalText,
		original_start : OptionalText,
		organizer : OptionalText,
		creator : OptionalText,
		meeting_code : OptionalText,
	}

	# One page of single events overlapping the window, ordered by start, cancelled ones included. All-day
	# events carry no time and are omitted; `all_day_omitted` counts them. Persist `next_page_token`.
	EventsPage : { events : List(Event), next_page_token : OptionalText, all_day_omitted : U64 }

	EventsOutcome : [Found(EventsPage), NotFound]

	EventOutcome : [Found(Event), AllDay, NotFound]

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

	# A calendar and the role one group holds in its ACL, read as the grant's Calendar reader.
	calendar : Context, Str, Str -> Observe(CalendarOutcome)
	calendar = |context, calendar_id, group_email| Resource.bind(context, "google_workspace").and_then(
		|resource| calendar_with(resource, calendar_id, group_email),
	)

	calendar_with : Resource, Str, Str -> Observe(CalendarOutcome)
	calendar_with = |resource, calendar_id, group_email| Observe.capability(
		"google_workspace.calendar.v1",
		Json.to_str({ handle: Resource.token(resource), calendar_id, group_email }),
	).and_then(
		|raw| {
			parsed : Try(CalendarOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_workspace_calendar"))
		},
	)

	# One page of events in a window of at most 31 days. Bounds are RFC 3339 with an offset and whole seconds.
	calendar_events : Context, Str, Str, Str, OptionalText -> Observe(EventsOutcome)
	calendar_events = |context, calendar_id, time_min, time_max, page_token| Resource.bind(
		context,
		"google_workspace",
	).and_then(|resource| calendar_events_with(resource, calendar_id, time_min, time_max, page_token))

	calendar_events_with : Resource, Str, Str, Str, OptionalText -> Observe(EventsOutcome)
	calendar_events_with = |resource, calendar_id, time_min, time_max, page_token| Observe.capability(
		"google_workspace.calendar_events.v1",
		Json.to_str({ handle: Resource.token(resource), calendar_id, time_min, time_max, page_token }),
	).and_then(
		|raw| {
			parsed : Try(EventsOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_workspace_events"))
		},
	)

	calendar_event : Context, Str, Str -> Observe(EventOutcome)
	calendar_event = |context, calendar_id, event_id| Resource.bind(context, "google_workspace").and_then(
		|resource| calendar_event_with(resource, calendar_id, event_id),
	)

	calendar_event_with : Resource, Str, Str -> Observe(EventOutcome)
	calendar_event_with = |resource, calendar_id, event_id| Observe.capability(
		"google_workspace.calendar_event.v1",
		Json.to_str({ handle: Resource.token(resource), calendar_id, event_id }),
	).and_then(
		|raw| {
			parsed : Try(EventOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_workspace_event"))
		},
	)
}
