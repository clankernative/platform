import JsonValue
import Names

## A decoded input kind. Catalog resolves every Reference against its own models
## before constructing a checked catalog; this type alone is not that proof.
Field := [
	Integer,
	Unsigned(Str),
	RowVersion,
	Text,
	Boolean,
	OptionalText,
	Reference(Names.Identifier),
	ModelReference(Names.Identifier, Str),
	IdCursor,
	TextDomain(Names.RocType),
	StandardText(Names.RocType),
	WebUrl,
	Cursor,
	PageSize,
].{
	from_json : JsonValue -> Try(Field, [BadJson(Str)])
	from_json = |node| match node {
		JsonValue.String("integer") => Ok(Integer)
		JsonValue.Object([("unsigned", JsonValue.String(kind))]) if ["U8", "U16", "U32", "U64"]
			.contains(kind) => Ok(Unsigned(kind))
		JsonValue.String("row_version") => Ok(RowVersion)
		JsonValue.String("text") => Ok(Text)
		JsonValue.String("boolean") => Ok(Boolean)
		JsonValue.String("optional_text") => Ok(OptionalText)
		JsonValue.String("web_url") => Ok(WebUrl)
		JsonValue.String("id_cursor") => Ok(IdCursor)
		JsonValue.String("cursor") => Ok(Cursor)
		JsonValue.String("page_size") => Ok(PageSize)
		JsonValue.Object([("reference", target)]) => {
			target.keys(["target"])?
			name =
				Names.Identifier.from_str(target.get("target")?.string()?)
					.map_err(|_| BadJson("invalid reference target name"))?
			Ok(Reference(name))
		}
		JsonValue.Object([("model_reference", target)]) => {
			target.keys(["target", "prefix"])?
			name =
				Names.Identifier.from_str(target.get("target")?.string()?)
					.map_err(|_| BadJson("invalid reference target"))?
			prefix =
				Names.Identifier.from_str(target.get("prefix")?.string()?)
					.map_err(|_| BadJson("invalid reference prefix"))?
			Ok(ModelReference(name, prefix.to_str()))
		}
		JsonValue.Object([("text_domain", domain)]) => {
			domain.keys(["roc_type"])?
			name =
				Names.RocType.from_str(domain.get("roc_type")?.string()?)
					.map_err(|_| BadJson("invalid text domain type name"))?
			Ok(TextDomain(name))
		}
		JsonValue.Object([("standard_text", domain)]) => {
			domain.keys(["domain"])?
			name =
				Names.RocType.from_str(domain.get("domain")?.string()?)
					.map_err(|_| BadJson("invalid standard domain type"))?
			Ok(StandardText(name))
		}
		_ => Err(BadJson("unsupported or ambiguous input kind"))
	}

	# Separate arms avoid a pinned-compiler miscompilation of an or-pattern
	# binding the same name from one-field and two-field tag payloads.
	reference_target : Field -> [NoReference, Target(Names.Identifier)]
	reference_target = |field| match field {
		Reference(name) => Target(name)
		ModelReference(name, _) => Target(name)
		_ => NoReference
	}

	info = |field| match field {
		IdCursor => {
			json_type: "string",
			roc_type: "Cursor",
			nullable: Bool.False,
			description: "Use an empty string for the first page, or the previous page's cursor.",
			example: Json.to_str(""),
		}
		ModelReference(target, prefix) => {
			json_type: "string",
			roc_type: "Ref(${target.to_str()})",
			nullable: Bool.False,
			description: "A ${target.to_str()} record ID with prefix ${prefix}_ and a UUIDv7 suffix.",
			example: Json.to_str("${prefix}_01h455vb4pex5vsknk084sn02q"),
		}
		Cursor => {
			json_type: "string",
			roc_type: "Cursor",
			nullable: Bool.False,
			description: "A pagination cursor; use \"0\" for the first page.",
			example: Json.to_str("0"),
		}
		PageSize => {
			json_type: "integer",
			roc_type: "PageSize",
			nullable: Bool.False,
			description: "Number of records, from 1 to 100.",
			example: "20",
		}
		Integer => {
			json_type: "integer",
			roc_type: "I64",
			nullable: Bool.False,
			description: "A signed 64-bit integer.",
			example: "1",
		}
		Unsigned(kind) => {
			json_type: "integer",
			roc_type: kind,
			nullable: Bool.False,
			description: "An unsigned ${kind} integer.",
			example: "0",
		}
		RowVersion => {
			json_type: "integer",
			roc_type: "RowVersion",
			nullable: Bool.False,
			description: "A positive unsigned 64-bit row revision.",
			example: "1",
		}
		Text => {
			json_type: "string",
			roc_type: "Str",
			nullable: Bool.False,
			description: "UTF-8 text, at most 16384 bytes.",
			example: Json.to_str("example"),
		}
		Boolean => {
			json_type: "boolean",
			roc_type: "Bool",
			nullable: Bool.False,
			description: "A JSON boolean: true or false.",
			example: "false",
		}
		OptionalText => {
			json_type: "string | object",
			roc_type: "[None, Some(Str)]",
			nullable: Bool.False,
			description: "Use \"None\" for no value or {\"Some\": \"text\"} for text (up to 16384 bytes). The field must be supplied.",
			example: Json.to_str("None"),
		}
		Reference(target) => {
			json_type: "string",
			roc_type: "Ref(${target.to_str()})",
			nullable: Bool.False,
			description: "ID of a ${target.to_str()} record, encoded as a positive decimal string.",
			example: Json.to_str("1"),
		}
		TextDomain(roc_type) => {
			json_type: "string",
			roc_type: roc_type.to_str(),
			nullable: Bool.False,
			description: "Text validated by the app's ${roc_type.to_str()} constructor.",
			example: Json.to_str("example"),
		}
		StandardText(domain) => {
			json_type: "string",
			roc_type: "Text(${domain.to_str()})",
			nullable: Bool.False,
			description: "Text governed by the admitted ${
				domain
					.to_str()
			} domain rules; see the shared API contract for bounds.",
			example: Json.to_str("example"),
		}
		WebUrl => {
			json_type: "string",
			roc_type: "WebUrl",
			nullable: Bool.False,
			description: "An HTTPS URL, at most 2048 UTF-8 bytes, without credentials or whitespace.",
			example: Json.to_str("https://example.com/plan"),
		}
	}
}

expect match JsonValue.parse("\"optional_text\"") {
	Ok(node) => match Field.from_json(node) {
		Ok(value) => Field.info(value).example == "\"None\"" and !Field.info(value).nullable
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}
