import Observe
import Effects
import Resource
import Context
import Api

# Organization reads through a keyless service account: Directory reads as the account itself, Calendar
# reads by domain-wide delegation as the grant's Calendar reader. Every action has a fixed scope and
# identity; an application names groups, members, calendars and events inside its grant, never a subject,
# scope or URL. The one write shares a Meet artifact's file with a group as reader.
GoogleWorkspace :: [].{
	share_effect = Api.external("google_workspace.share_artifact.v1")

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

	# Every Calendar read is bounded by the reader's own ACL rule: `NotShared` when the calendar exists for the
	# reader but not through an explicit `writer` or `owner` rule for it (a group, domain or default rule never
	# counts); `NotFound` when the reader cannot see a calendar with that ID at all.
	CalendarOutcome : [Found(Calendar), NotShared, NotFound]

	# RFC 3339 with an offset, as Google reports them.
	Times : { start : Str, end : Str }

	# Only a cancelled event may lack its times: Google may report a cancelled exception by id alone.
	EventStatus : [Confirmed(Times), Tentative(Times), Cancelled(Times), CancelledUntimed]

	Visibility : [Default, Public, Private, Confidential]

	# A timed event. `original_start` is set on a recurring instance; `meeting_code` is a Meet `xxx-xxxx-xxx` code.
	Event : {
		id : Str,
		status : EventStatus,
		visibility : Visibility,
		original_start : OptionalText,
		organizer : OptionalText,
		creator : OptionalText,
		meeting_code : OptionalText,
	}

	# One page of single events overlapping the window, ordered by start, cancelled ones included. All-day
	# events, including cancelled instances of an all-day series, carry no time and are omitted;
	# `all_day_omitted` counts them. `next_page_token` is opaque and bound to the calendar and window that issued
	# it: persist it, and send it back only with exactly those. Any other continuation is refused with
	# `google_workspace_request_invalid` before anything is sent; start the query again without a token.
	EventsPage : { events : List(Event), next_page_token : OptionalText, all_day_omitted : U64 }

	EventsOutcome : [Found(EventsPage), NotShared, NotFound]

	EventOutcome : [Found(Event), AllDay, NotShared, NotFound]

	# Where a recording, smart note or transcript is in Meet's progression.
	ArtifactState : [Started, Ended, FileGenerated]

	# `file_id` is the Drive file Meet saved the recording to, once it has.
	Recording : { name : Str, state : ArtifactState, file_id : OptionalText }

	# A smart note or transcript; `document_id` is its Docs document, once saved.
	Document : { name : Str, state : ArtifactState, document_id : OptionalText }

	# One conference in the event's space; a rejoin is another. `end_time` is unset while it is ongoing.
	ConferenceRecord : {
		name : Str,
		space : Str,
		start_time : Str,
		end_time : OptionalText,
		recordings : List(Recording),
		smart_notes : List(Document),
		transcripts : List(Document),
	}

	# Read as `owner`, always the event's creator: a person in the grant's email domain who is also the organizer,
	# or whose event's organizer is a group or resource calendar. Records are latest start first.
	EventConferences : { owner : Str, meeting_code : Str, records : List(ConferenceRecord) }

	# `NoOwner`: nobody in the grant's email domain owns the event. `NoMeeting`: it has no Meet code. `Conflict`: the
	# code's records in the event's window are in more than one space.
	EventConferencesOutcome : [Found(EventConferences), NoOwner, NoMeeting, Conflict, AllDay, NotShared, NotFound]

	Permission : { permission_id : Str }

	# `Shared`: the group was given reader in this attempt. `AlreadyShared`: it already held reader or more and
	# nothing was created. `NotReady`: Meet has not generated the file yet. `GroupNotFound`: the Directory knows no
	# such group. `GroupNotPrimary`: the address is an alias; only a group's primary address is shared with.
	# `SharingRefused`: Drive refused the request itself, for a sharing policy, and the group holds nothing. The
	# rest mean what they mean for `event_conferences`; `NotFound` also covers an artifact of another event and a
	# file the owner cannot see.
	ShareOutcome : [
		Shared(Permission),
		AlreadyShared(Permission),
		NotReady,
		GroupNotFound,
		GroupNotPrimary,
		SharingRefused,
		Conflict,
		NoOwner,
		NoMeeting,
		AllDay,
		NotShared,
		NotFound,
	]

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

	# One page of events in a window of at most 31 days. Bounds are RFC 3339 with an offset and whole seconds. A
	# `page_token` must be the `next_page_token` this same calendar and window returned.
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

	# An event's Meet conferences, with their recordings, smart notes and transcripts.
	event_conferences : Context, Str, Str -> Observe(EventConferencesOutcome)
	event_conferences = |context, calendar_id, event_id| Resource.bind(context, "google_workspace").and_then(
		|resource| event_conferences_with(resource, calendar_id, event_id),
	)

	event_conferences_with : Resource, Str, Str -> Observe(EventConferencesOutcome)
	event_conferences_with = |resource, calendar_id, event_id| Observe.capability(
		"google_workspace.event_conferences.v1",
		Json.to_str({ handle: Resource.token(resource), calendar_id, event_id }),
	).and_then(
		|raw| {
			parsed : Try(EventConferencesOutcome, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_workspace_event_conferences"))
		},
	)

	# What to share: `artifact` is the exact Meet name `event_conferences` reports for that event, and
	# `group_email` is the group's primary address.
	ShareArtifact : { calendar_id : Str, event_id : Str, artifact : Str, group_email : Str }

	# Share one artifact of one event with one group as reader, as the event's owner. The share lists before it
	# creates, and an attempt whose create reply is lost lists again, so it never creates twice. An outcome that
	# stays unknown holds the share's budget until an operator reconciles it; give shares their own budget.
	share_artifact : Resource, ShareArtifact -> Effects(ShareOutcome)
	share_artifact = |resource, share| Effects.capability(
		"google_workspace.share_artifact.v1",
		Json.to_str({
			handle: Resource.token(resource),
			calendar_id: share.calendar_id,
			event_id: share.event_id,
			artifact: share.artifact,
			group_email: share.group_email,
		}),
	).and_then(
		|raw| {
			parsed : Try(ShareOutcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_google_workspace_share"))
		},
	)
}
