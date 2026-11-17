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

	UserPath : { customer_id : Str, actor : Str, user_path : Str, captured_at : I64 }

	# A complete hierarchy handed to this invocation. There is no expiry: its pages
	# exist only until this preparation ends, so persist what you keep. `id` is
	# the content identity; an unchanged hierarchy delivers the same `id`.
	HierarchyDelivery : {
		id : Str,
		customer_id : Str,
		org_unit_count : U64,
		page_count : U64,
		captured_at : I64,
	}

	# At most 256 units, one `Tx.create_many` batch, in stable ID order.
	DeliveryPage : { items : List(OrgUnit), page : U64, done : Bool }

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

	deliver_hierarchy : Context -> Observe(HierarchyDelivery)
	deliver_hierarchy = |context| Resource.bind(context, "workspace_directory").and_then(deliver_hierarchy_with)

	deliver_hierarchy_with : Resource -> Observe(HierarchyDelivery)
	deliver_hierarchy_with = |resource| Observe.capability(
		"workspace_directory.hierarchy.v2",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(HierarchyDelivery, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_workspace_directory_delivery"))
		},
	)

	delivery_page_with : Resource, Str, U64 -> Observe(DeliveryPage)
	delivery_page_with = |resource, capture_id, page| Observe.capability(
		"workspace_directory.page.v2",
		Json.to_str({ handle: Resource.token(resource), capture_id, page }),
	).and_then(
		|raw| {
			parsed : Try(DeliveryPage, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_workspace_directory_delivery_page"))
		},
	)

}
