import JsonValue
import Names

## Only validated, bounded output shapes can reach catalog rendering.
OutputShape :: [
	Text,
	StandardText(Names.RocType),
	Integer,
	Unsigned(Str),
	RowVersion,
	ModelReference(Names.RocType),
	Cursor,
	PageSize,
	Boolean,
	Sequence(OutputShape),
	Page(OutputShape),
	Record(List((Names.Identifier, OutputShape))),
].{
	from_json : JsonValue -> Try(OutputShape, [BadJson(Str)])
	from_json = |node| decode(node, 0)

	to_type : OutputShape -> Str
	to_type = |shape| match shape {
		Text => "Str"
		StandardText(domain) => "Text(${domain.to_str()})"
		Integer => "I64"
		Unsigned(kind) => kind
		RowVersion => "RowVersion"
		ModelReference(name) => "Ref(${name.to_str()})"
		Cursor => "Cursor"
		PageSize => "PageSize"
		Boolean => "Bool"
		Sequence(item) => "List(${to_type(item)})"
		Page(item) => "CollectionPage(${to_type(item)})"
		Record(fields) => "{ ${
			Str.join_with(
				fields.map(|(name, field)| "${name.to_str()} : ${to_type(field)}"),
				", ",
			)
		} }"
	}

	nodes : OutputShape -> U64
	nodes = |shape| match shape {
		Text
		| StandardText(_)
		| Integer
		| Unsigned(_)
		| RowVersion
		| ModelReference(_)
		| Cursor
		| PageSize
		| Boolean => 1
		Sequence(item) | Page(item) => 1 + nodes(item)
		Record(fields) => 1 + fields.fold(0.U64, |count, field| count + nodes(field.1))
	}
}

decode : JsonValue, U64 -> Try(OutputShape, [BadJson(Str)])
decode = |node, depth| {
	if depth >= 16 {
		return Err(BadJson("output schema depth exceeds 16"))
	}
	match node {
		JsonValue.String("string") => Ok(OutputShape.Text)
		JsonValue.Object([("standard_text", domain)]) => {
			domain.keys(["domain"])?
			name =
				Names.RocType.from_str(domain.get("domain")?.string()?)
					.map_err(|_| BadJson("invalid output domain type"))?
			Ok(OutputShape.StandardText(name))
		}
		JsonValue.String("integer") => Ok(OutputShape.Integer)
		JsonValue.Object([("unsigned", JsonValue.String(kind))]) if ["U8", "U16", "U32", "U64"]
			.contains(kind) => Ok(OutputShape.Unsigned(kind))
		JsonValue.Object([("model_reference", reference)]) => {
			reference.keys(["roc_type", "prefix"])?
			_ =
				Names.Identifier.from_str(reference.get("prefix")?.string()?)
					.map_err(|_| BadJson("invalid output reference prefix"))?
			name =
				Names.RocType.from_str(reference.get("roc_type")?.string()?)
					.map_err(|_| BadJson("invalid output reference type"))?
			Ok(OutputShape.ModelReference(name))
		}
		JsonValue.String("row_version") => Ok(OutputShape.RowVersion)
		JsonValue.String("cursor") | JsonValue.String("id_cursor") => Ok(OutputShape.Cursor)
		JsonValue.String("page_size") => Ok(OutputShape.PageSize)
		JsonValue.String("boolean") => Ok(OutputShape.Boolean)
		JsonValue.Object([("collection_page", item)])
		| JsonValue.Object([("id_page", item)]) => decode(item, depth + 1).map_ok(|shape| OutputShape.Page(shape))
		JsonValue.Object([("list", item)]) => decode(item, depth + 1).map_ok(|shape| OutputShape.Sequence(shape))
		JsonValue.Object([("record", object)]) => {
			fields = object.object()?
			if fields.len() > 64 {
				return Err(BadJson("output record exceeds 64 fields"))
			}
			checked = decode_fields(fields, depth + 1, [])?
			Ok(OutputShape.Record(checked.sort_with(|a, b| Names.order(a.0.to_str(), b.0.to_str()))))
		}
		_ => Err(BadJson("unsupported output shape"))
	}
}

decode_fields :
	List((Str, JsonValue)),
	U64,
	List((Names.Identifier, OutputShape)) ->
		Try(List((Names.Identifier, OutputShape)), [BadJson(Str)])
decode_fields = |fields, depth, checked| match fields {
	[] => Ok(checked)
	[(name, node), .. as rest] => {
		key = Names.Identifier.from_str(name).map_err(|_| BadJson("invalid output field name"))?
		shape = decode(node, depth)?
		decode_fields(rest, depth, checked.append((key, shape)))
	}
}
