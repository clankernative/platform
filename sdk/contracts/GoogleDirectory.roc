import Observe
import Effects
import Resource
import Context
import Api

# Operator-scoped Google directory semantics. The current adapter is explicitly
# synthetic; passwords, provider credentials and group-target mappings stay native.
GoogleDirectory :: [].{
	create_effect = Api.external("google_directory.create_user.v1")

	patch_effect = Api.external("google_directory.patch_attributes.v1")

	group_effect = Api.external("google_directory.ensure_group_member.v1")

	OptionalText : [Some(Str), None]

	Snapshot : { id : Str, customer_id : Str }

	User : {
		id : Str,
		primary_email : Str,
		given_name : Str,
		family_name : Str,
		full_name : Str,
		org_unit_path : Str,
		thumbnail_photo_url : OptionalText,
		suspended : Bool,
	}

	Group : { id : Str, email : Str, name : Str }

	OrgUnit : { id : Str, path : Str, name : Str }

	Record : [User(User), Group(Group), OrgUnit(OrgUnit), Done]

	Attribute : { key : Str, value : Str }

	CreateUser : {
		given_name : Str,
		family_name : Str,
		primary_email : Str,
		personal_email : Str,
		org_unit_path : Str,
		start_date : Str,
	}

	PatchAttributes : { primary_email : Str, attributes : List(Attribute) }

	EnsureGroup : { primary_email : Str, group : Str }

	Problem : { code : Str, message : Str, retryable : Bool }

	CreatedUser : { id : Str, primary_email : Str }

	CreateOutcome : [Created(CreatedUser), Conflict(Problem), Failed(Problem)]

	PatchOutcome : [Patched, Failed(Problem)]

	GroupOutcome : [Added, AlreadyMember, Failed(Problem)]

	snapshot : Context -> Observe(Snapshot)
	snapshot = |context| Resource.bind(context, "google_directory").and_then(snapshot_with)

	snapshot_with : Resource -> Observe(Snapshot)
	snapshot_with = |resource| Observe.capability(
		"google_directory.snapshot.v1",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(Snapshot, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_directory_snapshot"))
		},
	)

	next_with : Resource, Str, U64 -> Observe(Record)
	next_with = |resource, snapshot_id, cursor| Observe.capability(
		"google_directory.record.v1",
		Json.to_str({ handle: Resource.token(resource), snapshot_id, cursor }),
	).and_then(
		|raw| {
			parsed : Try({ kind : Str, data : Str }, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_google_directory_record"))
		},
	).and_then(
		|envelope| match envelope.kind {
			"user" => {
				parsed : Try(User, _)
				parsed = Json.parse(envelope.data)
				Observe.from_host(parsed.map_err(|_| "invalid_google_directory_user")).map(|value| User(value))
			}
			"group" => {
				parsed : Try(Group, _)
				parsed = Json.parse(envelope.data)
				Observe.from_host(parsed.map_err(|_| "invalid_google_directory_group")).map(|value| Group(value))
			}
			"org_unit" => {
				parsed : Try(OrgUnit, _)
				parsed = Json.parse(envelope.data)
				Observe.from_host(parsed.map_err(|_| "invalid_google_directory_org_unit")).map(|value| OrgUnit(value))
			}
			"done" => Observe.value(Done)
			_ => Observe.from_host(Err("invalid_google_directory_record_kind"))
		},
	)

	create_user : Resource, CreateUser -> Effects(CreateOutcome)
	create_user = |resource, input| Effects.capability(
		"google_directory.create_user.v1",
		Json.to_str({ handle: Resource.token(resource), input }),
	).and_then(
		|raw| {
			parsed : Try(CreateOutcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_google_directory_create_outcome"))
		},
	)

	patch_attributes : Resource, PatchAttributes -> Effects(PatchOutcome)
	patch_attributes = |resource, input| Effects.capability(
		"google_directory.patch_attributes.v1",
		Json.to_str({ handle: Resource.token(resource), input }),
	).and_then(
		|raw| {
			parsed : Try(PatchOutcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_google_directory_patch_outcome"))
		},
	)

	ensure_group_member : Resource, EnsureGroup -> Effects(GroupOutcome)
	ensure_group_member = |resource, input| Effects.capability(
		"google_directory.ensure_group_member.v1",
		Json.to_str({ handle: Resource.token(resource), input }),
	).and_then(
		|raw| {
			parsed : Try(GroupOutcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_google_directory_group_outcome"))
		},
	)
}
