import Cli
import Field
import Names
import JsonValue
import OutputShape
import Problem

## A complete checked discovery catalog. No raw DTOs or construction APIs escape.
Catalog :: { operations : List(CheckedOperation), meaning : List(Meaning) }.{
	Meaning : {
		name : Str,
		description : Str,
		example_input_json : Str,
		inputs : List({ name : Str, description : Str }),
	}

	InputDto : { name : Str, json_type : Str, roc_type : Str, required : Bool, nullable : Bool, description : Str }

	OperationDto : {
		name : Str,
		kind : Str,
		effect : Str,
		description : Str,
		description_source : Str,
		input_type : Str,
		input_fields : List(InputDto),
		output_type : Str,
		example_input_json : Str,
	}

	ViewDto : { operation_count : U64, total_operations : U64, operations : List(OperationDto), example_note : Str }

	from_json : Str -> Try(Catalog, Problem)
	from_json = |raw| {
		if raw.count_utf8_bytes() > 1_048_576 {
			return Err(Problem.MetadataTooLarge)
		}
		node = JsonValue.parse(raw).map_err(|BadJson(detail)| Problem.InvalidArtifact(detail))?
		version =
			node
				.get("format")
				.map_err(|BadJson(detail)| Problem.InvalidCatalog(detail))?
				.u64()
				.map_err(|BadJson(detail)| Problem.InvalidCatalog(detail))?
		if version < 1 or version > 10 {
			return Err(Problem.UnsupportedArtifact(version))
		}
		check_catalog(node, version).map_err(|BadJson(detail)| Problem.InvalidCatalog(detail))
	}

	from_projection : Str -> Try(Catalog, Problem)
	from_projection = |raw| {
		node = JsonValue.parse(raw).map_err(|BadJson(detail)| Problem.InvalidCatalog(detail))?
		check_projection(node).map_err(|BadJson(detail)| Problem.InvalidCatalog(detail))
	}

	## A view can only select operations already belonging to its checked catalog.
	View :: { catalog : Catalog, selected : List(CheckedOperation) }.{
		names : View -> List(Names.Operation)
		names = |view| view.selected.map(|operation| body(operation).name)

		dto : View, Bool -> ViewDto
		dto = |view, demo| {
			operation_count: view.selected.len(),
			total_operations: view.catalog.operations.len(),
			operations: view.selected.map(|operation| operation_dto(operation, demo, view.catalog.meaning)),
			example_note: "Examples are illustrative JSON, not executed requests. Replace IDs and versions with current values; the runtime validates inputs and permissions.",
		}
	}

	select : Catalog, Cli.Filter -> Try(View, Problem)
	select = |catalog, filter| {
		selected = match filter {
			Cli.Filter.All => catalog.operations
			Cli.Filter.One(name) => catalog
				.operations
				.keep_if(|operation| body(operation).name.to_str() == name.to_str())
		}
		if selected.is_empty() {
			match filter {
				Cli.Filter.One(name) => return Err(
					Problem.OperationNotFound(
						name.to_str(),
						catalog.operations.map(|operation| body(operation).name.to_str()).sort_with(Names.order),
					),
				)
				Cli.Filter.All => return Err(Problem.InvalidCatalog("internal catalog invariant violated"))
			}
		}
		Ok(View.{ catalog, selected })
	}
}

NamedRecord : {
	name : Names.Identifier,
	roc_type : [Unnamed, Named(Names.RocType)],
	fields : List((Names.Identifier, Field)),
}

OperationBody : { name : Names.Operation, input : NamedRecord }

CheckedOperation := [
	Query(OperationBody, [Undeclared, Declared(OutputShape)]),
	Command(OperationBody, [Undeclared, Declared(OutputShape)]),
]

ForeignKey : { model : Str, field : Str, target : Str }

body : CheckedOperation -> OperationBody
body = |operation| match operation {
	CheckedOperation.Query(value, _) | CheckedOperation.Command(value, _) => value
}

check_catalog : JsonValue, U64 -> Try(Catalog, [BadJson(Str)])
check_catalog = |node, version| {
	node
		.keys([
			"format",
			"roc_version",
			"worker_digest",
			"schema_digest",
			"schema",
			"operations",
			"properties",
			"pages",
			"schedules",
			"assets",
			"web_resources",
			"outputs",
			"templates",
			"sources",
			"admission",
			"checked_types_digest",
			"declarations",
			"namespace",
		])?
	if node.get("admission")?.string()? != "local-spike-only" {
		return Err(BadJson("unsupported admission contract"))
	}
	compiler = node.get("roc_version")?.string()?
	if compiler.trim().is_empty() or compiler.count_utf8_bytes() > 128 {
		return Err(BadJson("invalid compiler version metadata"))
	}
	check_digest(node.get("worker_digest")?.string()?)?
	check_digest(node.get("schema_digest")?.string()?)?
	sources = node.get("sources")?.object()?
	if sources.len() > 2048 {
		return Err(BadJson("too many source identities"))
	}
	for (name, digest) in sources {
		_ = Names.LocalPath.from_str(name).map_err(|_| BadJson("invalid source path"))?
		check_digest(digest.string()?)?
	}
	check_versioned_collection(node, "properties", version, 2, Bool.True)?
	check_versioned_collection(node, "pages", version, 3, Bool.True)?
	check_versioned_collection(node, "assets", version, 4, Bool.False)?
	check_versioned_collection(node, "web_resources", version, 5, Bool.False)?
	check_versioned_collection(node, "templates", version, 6, Bool.False)?

	check_declarations(node, version)
}

check_projection : JsonValue -> Try(Catalog, [BadJson(Str)])
check_projection = |node| {
	node.keys(["version", "schema", "operations", "outputs", "meaning"])?
	if node.get("version")?.u64()? != 1 {
		return Err(BadJson("unsupported discovery projection version"))
	}
	catalog = check_declarations(node, 10)?
	meaning : List(Catalog.Meaning)
	meaning = Json.parse(node.get("meaning")?.string()?).map_err(|_| BadJson("invalid shared contract meaning"))?
	if
		meaning.len()
			!= catalog.operations.len()
			or !catalog
				.operations
				.all(|operation| meaning.keep_if(|entry| entry.name == body(operation).name.to_str()).len() == 1)
			{
				return Err(BadJson("shared meaning must cover every operation exactly once"))
			}
	for operation in catalog.operations {
		entry =
			meaning
				.find_first(|item| item.name == body(operation).name.to_str())
				.map_err(|_| BadJson("missing operation meaning"))?
		fields = body(operation).input.fields
		if
			entry.description.trim().is_empty()
				or entry.inputs.len()
					!= fields.len()
					or !fields
						.all(
							|
								field,
							|
								entry
									.inputs
									.keep_if(
										|input| input.name == field.0.to_str() and !input.description.trim().is_empty(),
									)
									.len()
									== 1,
						)
				{
					return Err(BadJson("shared meaning must cover every input exactly once"))
				}
	}
	Ok(Catalog.{ operations: catalog.operations, meaning })
}

check_declarations : JsonValue, U64 -> Try(Catalog, [BadJson(Str)])
check_declarations = |node, version| {
	schema = node.get("schema")?
	schema.keys(["models", "inputs", "foreign_keys", "indexes", "domains"])?
	models = decode_records(schema.get("models")?.object()?, Bool.True, version, [])?
	inputs = decode_records(schema.get("inputs")?.object()?, Bool.False, version, [])?
	if models.is_empty() or models.len() > 32 or inputs.is_empty() or inputs.len() > 64 {
		return Err(BadJson("model or input registration count is outside platform bounds"))
	}
	validate_graph(models, inputs, schema.get("foreign_keys")?.array()?, version)?
	outputs = decode_outputs(optional_object(node, "outputs")?, [], 0)?
	if version < 6 and !outputs.is_empty() {
		return Err(BadJson("typed outputs require artifact format 6 or later"))
	}
	raw_operations = node.get("operations")?.array()?
	if raw_operations.is_empty() or raw_operations.len() > 128 {
		return Err(BadJson("catalog must contain 1 to 128 operations"))
	}
	operations = decode_operations(raw_operations, inputs, outputs, version, [])?
	names = operations.map(|operation| body(operation).name.to_str())
	require_unique(names, "duplicate operation name")?
	Ok(
		Catalog.{
			operations: operations
				.sort_with(|left, right| Names.order(operation_sort_key(left), operation_sort_key(right))),
			meaning: [],
		},
	)
}

check_digest : Str -> Try({}, [BadJson(Str)])
check_digest = |value| {
	bytes = value.drop_prefix("sha256:").to_utf8()
	if
		!value.starts_with("sha256:")
			or bytes.len() != 64 or !bytes.all(|byte| (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))
			{
				return Err(BadJson("invalid SHA-256 identity syntax"))
			}
	Ok({})
}

check_versioned_collection : JsonValue, Str, U64, U64, Bool -> Try({}, [BadJson(Str)])
check_versioned_collection = |node, key, version, introduced, array| {
	match node.optional(key)? {
		Absent => Ok({})
		Present(content) => {
			length = if array content.array()?.len() else content.object()?.len()
			if version < introduced and length > 0 {
				return Err(BadJson("metadata is incompatible with its artifact version"))
			}
			Ok({})
		}
	}
}

optional_object : JsonValue, Str -> Try(List((Str, JsonValue)), [BadJson(Str)])
optional_object = |node, key| match node.optional(key)? {
	Absent => Ok([])
	Present(content) => content.object()
}

decode_records : List((Str, JsonValue)), Bool, U64, List(NamedRecord) -> Try(List(NamedRecord), [BadJson(Str)])
decode_records = |records, model, version, done| match records {
	[] => Ok(done)
	[(key, node), .. as rest] => {
		name = Names.Identifier.from_str(key).map_err(|_| BadJson("invalid model or input name"))?
		node.keys(["roc_type", "fields"])?
		roc_type = match node.optional("roc_type")? {
			Absent => Unnamed
			Present(value) => Named(
				Names.RocType.from_str(value.string()?).map_err(|_| BadJson("invalid qualified Roc type name"))?,
			)
		}
		if model and version >= 2 {
			match roc_type {
				Unnamed => return Err(BadJson("typed artifacts require nominal models"))
				Named(_) => {}
			}
		}
		raw_fields = node.get("fields")?.object()?
		if raw_fields.len() > 32 or (model and raw_fields.is_empty()) {
			return Err(BadJson("invalid field count"))
		}
		fields = decode_fields(raw_fields, model, [])?
		decode_records(rest, model, version, done.append({ name, roc_type, fields }))
	}
}

decode_fields :
	List((Str, JsonValue)),
	Bool,
	List((Names.Identifier, Field)) ->
		Try(List((Names.Identifier, Field)), [BadJson(Str)])
decode_fields = |fields, model, done| match fields {
	[] => Ok(done.sort_with(|a, b| Names.order(a.0.to_str(), b.0.to_str())))
	[(key, node), .. as rest] => {
		name = Names.Identifier.from_str(key).map_err(|_| BadJson("invalid field identifier"))?
		if model and ["id", "version", "created_at"].contains(key) {
			return Err(BadJson("reserved persistent model field"))
		}
		kind = Field.from_json(node)?
		decode_fields(rest, model, done.append((name, kind)))
	}
}

validate_graph : List(NamedRecord), List(NamedRecord), List(JsonValue), U64 -> Try({}, [BadJson(Str)])
validate_graph = |models, inputs, raw_fks, version| {
	nominals = models.fold(
		[],
		|all, model| match model.roc_type {
			Unnamed => all
			Named(name) => all.append(name.to_str())
		},
	)
	require_unique(nominals, "duplicate nominal model identity")?
	for record in models.concat(inputs) {
		for (_, kind) in record.fields {
			match Field.reference_target(kind) {
				Target(target) => {
					model = lookup_record(models, target.to_str())?
					match model.roc_type {
						Unnamed => return Err(BadJson("reference target has no nominal model identity"))
						Named(_) => {}
					}
				}
				_ => {}
			}
		}
	}
	fks = decode_fks(raw_fks, models, version, [])?
	require_unique(fks.map(|fk| "${fk.model}.${fk.field}"), "ambiguous foreign key")?
	for model in models {
		for (name, kind) in model.fields {
			match Field.reference_target(kind) {
				Target(target) => {
					if
						!fks
							.any(
								|
									fk,
								|
									fk.model
										== model.name.to_str()
										and fk.field == name.to_str() and fk.target == target.to_str(),
							)
							{
								return Err(BadJson("missing reference-derived foreign key"))
							}
				}
				_ => {}
			}
		}
	}
	input_handles =
		inputs
			.fold(
				[],
				|
					all,
					input,
				|
					all
						.append(input.name.to_str())
						.concat(input.fields.map(|field| "${input.name.to_str()}_${field.0.to_str()}")),
			)
	require_unique(input_handles, "generated Inputs name collision")?
	if version >= 2 {
		data_handles = models.fold(
			["snapshot"],
			|all, model| all.append(model.name.to_str()).append("all_${model.name.to_str()}").concat(
				model.fields.fold(
					[],
					|handles, field| match Field.reference_target(field.1) {
						Target(_) => handles.append("${model.name.to_str()}_by_${field.0.to_str()}")
						_ => handles
					},
				),
			),
		)
		require_unique(data_handles, "generated Data name collision")?
	}
	Ok({})
}

decode_fks : List(JsonValue), List(NamedRecord), U64, List(ForeignKey) -> Try(List(ForeignKey), [BadJson(Str)])
decode_fks = |nodes, models, version, done| match nodes {
	[] => Ok(done)
	[node, .. as rest] => {
		node.keys(["model", "field", "target"])?
		model = node.get("model")?.string()?
		field = node.get("field")?.string()?
		target = node.get("target")?.string()?
		record = lookup_record(models, model)?
		_ = lookup_record(models, target)?
		entry =
			record
				.fields
				.keep_if(|item| item.0.to_str() == field)
				.first()
				.map_err(|_| BadJson("foreign key references a missing field"))?
		match Field.reference_target(entry.1) {
			Target(name) => if name.to_str() != target {
				return Err(BadJson("foreign key disagrees with typed reference"))
			}
			NoReference => match entry.1 {
				Field.Integer => if version >= 2 {
					return Err(BadJson("typed foreign keys require reference fields"))
				}
				_ => return Err(BadJson("foreign key requires a reference or legacy integer field"))
			}
		}

		decode_fks(rest, models, version, done.append({ model, field, target }))
	}
}

lookup_record : List(NamedRecord), Str -> Try(NamedRecord, [BadJson(Str)])
lookup_record =
	|
		records,
		key,
	|
		records
			.keep_if(|record| record.name.to_str() == key)
			.first()
			.map_err(|_| BadJson("unresolved model or input contract"))

require_unique : List(Str), Str -> Try({}, [BadJson(Str)])
require_unique = |items, detail| if Set.from_list(items).len() == items.len() Ok({}) else Err(BadJson(detail))

decode_outputs : List((Str, JsonValue)), List((Str, OutputShape)), U64 -> Try(List((Str, OutputShape)), [BadJson(Str)])
decode_outputs = |outputs, done, count| match outputs {
	[] => Ok(done)
	[(key, node), .. as rest] => {
		if done.len() >= 64 {
			return Err(BadJson("too many output registrations"))
		}
		_ = Names.Identifier.from_str(key).map_err(|_| BadJson("invalid output registration name"))?
		node.keys(["roc_type", "shape"])?
		shape = OutputShape.from_json(node.get("shape")?)?
		annotation = node.get("roc_type")?.string()?
		check_annotation(annotation, shape.to_type())?
		next_count = count + shape.nodes()
		if next_count > 1024 {
			return Err(BadJson("output schema node budget exceeded"))
		}
		decode_outputs(rest, done.append((key, shape)), next_count)
	}
}

check_annotation : Str, Str -> Try({}, [BadJson(Str)])
check_annotation = |annotation, canonical| {
	if annotation.is_empty() or annotation.count_utf8_bytes() > 32_768 {
		return Err(BadJson("invalid output annotation length"))
	}
	compact = annotation.replace_each(" ", "")
	if
		["Str", "I64", "Bool", "U8", "U16", "U32", "U64", "RowVersion", "Cursor", "PageSize"].contains(annotation)
			or compact.starts_with("{") or compact.starts_with("List(") or compact.starts_with("CollectionPage(")
			{
				if compact != canonical.replace_each(" ", "") {
					return Err(BadJson("output annotation disagrees with its checked shape"))
				}
			}
				else
					{
						_ = Names.RocType.from_str(annotation).map_err(|_| BadJson("invalid output annotation"))?
						first = annotation.split_on(".").first() ?? ""
						if ["Output", "Outputs", "Json", "List"].contains(first) {
							return Err(BadJson("reserved output annotation"))
						}
					}
	Ok({})
}

decode_operations :
	List(JsonValue),
	List(NamedRecord),
	List((Str, OutputShape)),
	U64,
	List(CheckedOperation) ->
		Try(List(CheckedOperation), [BadJson(Str)])
decode_operations = |nodes, inputs, outputs, version, done| match nodes {
	[] => Ok(done)
	[node, .. as rest] => {
		node.keys(["name", "kind", "input_type", "output_type"])?
		name = Names.Operation.from_str(node.get("name")?.string()?).map_err(|_| BadJson("invalid operation name"))?
		input = lookup_record(inputs, node.get("input_type")?.string()?)?
		output_name = match node.optional("output_type")? {
			Absent => Absent
			Present(value) => {
				# The platform wire format uses an empty string for undeclared output.
				text = value.string()?
				if
					text.is_empty()
					Absent
				else
					Present(Names.Identifier.from_str(text).map_err(|_| BadJson("invalid output registration name"))?)
			}
		}
		kind = node.get("kind")?.string()?
		if kind == "completion" and version >= 9 {
			if output_name != Absent {
				return Err(BadJson("private completions cannot declare outputs"))
			}
			return decode_operations(rest, inputs, outputs, version, done)
		}
		operation = match kind {
			"query" => {
				output = match output_name {
					Absent => Undeclared
					Present(output_id) => {
						if version < 6 {
							return Err(BadJson("typed query output requires format 6 or later"))
						}
						shape =
							outputs
								.keep_if(|pair| pair.0 == output_id.to_str())
								.first()
								.map_err(|_| BadJson("unresolved output contract"))?.1
						Declared(shape)
					}
				}
				CheckedOperation.Query({ name, input }, output)
			}
			"command" => {
				output = match output_name {
					Present(output_id) => {
						if version < 10 {
							return Err(BadJson("typed command outputs require format 10"))
						}
						shape =
							outputs
								.keep_if(|pair| pair.0 == output_id.to_str())
								.first()
								.map_err(|_| BadJson("unresolved command output"))?.1
						Declared(shape)
					}
					Absent => Undeclared
				}
				CheckedOperation.Command({ name, input }, output)
			}
			_ => return Err(BadJson("unsupported operation kind"))
		}
		decode_operations(rest, inputs, outputs, version, done.append(operation))
	}
}

operation_sort_key : CheckedOperation -> Str
operation_sort_key = |operation| "${
	match operation {
		CheckedOperation.Query(_, _) => "0"
		CheckedOperation.Command(_, _) => "1"
	}
}${body(operation).name.to_str()}"

operation_dto : CheckedOperation, Bool, List(Catalog.Meaning) -> Catalog.OperationDto
operation_dto = |operation, demo, meanings| {
	value = body(operation)
	kind = match operation {
		CheckedOperation.Query(_, _) => "query"
		CheckedOperation.Command(_, _) => "command"
	}
	effect = match operation {
		CheckedOperation.Query(_, _) => "read"
		CheckedOperation.Command(_, _) => "write"
	}
	name = value.name.to_str()
	meaning = meanings.find_first(|entry| entry.name == name)
	input_fields = value.input.fields.map(
		|(key, field)| {
			info = Field.info(field)
			description = match meaning {
				Ok(entry) => match entry.inputs.find_first(|input| input.name == key.to_str()) {
					Ok(input) => input.description
					Err(_) => info.description
				}
				Err(_) => if demo field_copy(key.to_str(), info.description) else info.description
			}
			{
				name: key.to_str(),
				json_type: info.json_type,
				roc_type: info.roc_type,
				required: Bool.True,
				nullable: info.nullable,
				description,
			}
		},
	)
	example_input_json =
		"{${
			Str.join_with(
				value
					.input
					.fields
					.map(
						|
							(key, field),
						|
							"${Json.to_str(key.to_str())}: ${
								if
									demo
									example(key.to_str(), Field.info(field).example)
								else
									Field.info(field).example
							}",
					),
				", ",
			)
		}}"
	output_type = match operation {
		CheckedOperation.Query(_, Declared(shape)) | CheckedOperation.Command(_, Declared(shape)) => shape.to_type()
		CheckedOperation.Query(_, Undeclared)
		| CheckedOperation.Command(_, Undeclared) => "Not declared in this artifact"
	}
	{
		name,
		kind,
		effect,
		description: match meaning {
			Ok(entry) => entry.description
			Err(_) => if
				demo
				operation_copy(name)
			else
				if
					kind == "query"
					"Read application data using the inputs below."
				else
					"Run an application transaction that may write data."
		},
		description_source: match meaning {
			Ok(_) => "application_contract"
			Err(_) => if demo "prototype_copy" else "type_metadata"
		},
		input_type: match value.input.roc_type {
			Unnamed => value.input.name.to_str()
			Named(roc_type) => roc_type.to_str()
		},
		input_fields,
		output_type,
		example_input_json: match meaning {
			Ok(entry) => entry.example_input_json
			Err(_) => example_input_json
		},
	}
}

# Editorial copy belongs only to the bundled, pinned demo. Live contracts are
# never assigned semantics based on an operation or field naming convention.
operation_copy : Str -> Str
operation_copy = |name| match name {
	"links.list" => "Browse links in ID order, with a cursor for the next page. Includes archived links."
	"links.detail" => "Read one link, including its current version and archive status."
	"links.create" => "Save a titled URL to the shared directory. Creates an unarchived link."
	"links.archive" => "Archive a link using the version you last read. Rejects a stale version or an already archived link."
	_ => "Inspect the typed contract below."
}

field_copy : Str, Str -> Str
field_copy = |name, fallback| match name {
	"after" => "Pagination cursor. Use 0 for the first page, then the previous result's next_after."
	"limit" => "Maximum records to return on this page (1 to 100)."
	"link_id" => "Link ID as a positive decimal string, for example \"1\"."
	"expected_version" => "Version from a fresh links.detail result; prevents overwriting a concurrent change."
	"title" => "A nonblank title, at most 200 UTF-8 bytes."
	"destination" => "An HTTPS URL, at most 2048 UTF-8 bytes."
	_ => fallback
}

example : Str, Str -> Str
example = |name, fallback| match name {
	"after" => "0"
	"limit" => "20"
	"expected_version" => "1"
	"title" => Json.to_str("Quarterly plan")
	_ => fallback
}
