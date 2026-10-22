import Observe
import Resource
import Context

WorkspaceDirectory :: [].{
	OptionalText : [Some(Str), None]

	OrgUnit : {
		id : Str,
		name : Str,
		path : Str,
		parent_id : OptionalText,
		parent_path : OptionalText,
	}

	Capture : {
		id : Str,
		customer_id : Str,
		actor : Str,
		user_path : Str,
		org_unit_count : U64,
		captured_at : I64,
		source_captured_at : I64,
		expires_at : I64,
	}

	UserPath : { customer_id : Str, actor : Str, user_path : Str, captured_at : I64 }

	HierarchyCapture : {
		id : Str,
		customer_id : Str,
		actor : Str,
		org_unit_count : U64,
		captured_at : I64,
		source_captured_at : I64,
		expires_at : I64,
	}

	Page : { items : List(OrgUnit), next : U64, done : Bool }

	capture : Context -> Observe(Capture)
	capture = |context| Resource.bind(context, "workspace_directory").and_then(capture_with)

	capture_with : Resource -> Observe(Capture)
	capture_with = |resource| Observe.capability(
		"workspace_directory.capture.v1",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(Capture, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_workspace_directory_capture"))
		},
	)

	user_path : Context -> Observe(UserPath)
	user_path = |context| Resource.bind(context, "workspace_directory").and_then(user_path_with)

	user_path_with : Resource -> Observe(UserPath)
	user_path_with = |resource| Observe.capability(
		"workspace_directory.user_path.v1",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(UserPath, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_workspace_directory_user_path"))
		},
	)

	capture_hierarchy : Context -> Observe(HierarchyCapture)
	capture_hierarchy = |context| Resource.bind(context, "workspace_directory").and_then(capture_hierarchy_with)

	capture_hierarchy_with : Resource -> Observe(HierarchyCapture)
	capture_hierarchy_with = |resource| Observe.capability(
		"workspace_directory.hierarchy.v1",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(HierarchyCapture, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_workspace_directory_hierarchy"))
		},
	)

	page_with : Resource, Str, U64 -> Observe(Page)
	page_with = |resource, capture_id, offset| Observe.capability(
		"workspace_directory.page.v1",
		Json.to_str({ handle: Resource.token(resource), capture_id, offset }),
	).and_then(
		|raw| {
			parsed : Try(Page, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_workspace_directory_page"))
		},
	)
}
