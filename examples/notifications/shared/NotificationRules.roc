# The notification domain uses UTF-16 limits to preserve the source application's
# limits, including for astral Unicode characters. Substitution is one pass.
NotificationRules :: [].{
	Field : { name : Str, kind : Str, max_length : U64, choices : List(Str) }

	Value : { name : Str, kind : Str, text : Str, integer : I64, boolean : Bool }

	Finding : { field : Str, code : Str }

	field_input = {
		description: "Immutable field declarations, at most 20.",
		each: {
			name: "Lowercase field name.",
			kind: "text, integer, boolean or enum.",
			max_length: "1..1000 for text; zero for other kinds.",
			choices: {
				description: "Ordered enum choices; empty for other kinds.",
				each: "A unique nonblank choice, up to 100 UTF-16 units.",
			},
		},
	}

	value_input = {
		description: "Named values, at most 20.",
		each: {
			name: "Declared field name.",
			kind: "text, integer or boolean; enums use text.",
			text: "Text or enum value.",
			integer: "Signed integer value.",
			boolean: "Boolean value.",
		},

	}

	length : Str -> U64
	length =
		|
			text,
		|
			text
				.to_utf8()
				.fold(
					0,
					|count, byte| count + if byte < 128 or (byte >= 192 and byte < 240) 1 else if byte >= 240 2 else 0,
				)

	valid_app_id : Str -> Bool
	valid_app_id = |value| {
		bytes = value.to_utf8()
		!bytes.is_empty() and bytes.len() <= 63 and bytes.all(|byte| alphanumeric(byte) or byte == 45)
			and (match bytes.first() {
				Ok(byte) => alphanumeric(byte)
				Err(_) => Bool.False
			})
				and (match bytes.last() {
					Ok(byte) => alphanumeric(byte)
					Err(_) => Bool.False
				})
	}

	valid_event_key : Str -> Bool
	valid_event_key = |value| identifier(value, 80, Bool.True)

	valid_field_name : Str -> Bool
	valid_field_name = |value| identifier(value, 64, Bool.False)

	validate_schema : List(Field) -> List(Finding)
	validate_schema = |fields| {
		if fields.len() > 20 {
			return [{ field: "fields", code: "too_many_fields" }]
		}
		global = if fields.len() > 20 [{ field: "fields", code: "too_many_fields" }] else []
		duplicates =
			if
				fields.any(|field| fields.keep_if(|other| other.name == field.name).len() > 1)
				[{ field: "fields", code: "duplicate_field" }]
			else
				[]
		global.concat(duplicates).concat(
			fields.fold(
				[],
				|findings, field| {
					location = if valid_field_name(field.name) field.name else "fields"
					name = if valid_field_name(field.name) [] else [{ field: location, code: "invalid_field_name" }]
					type_findings = match field.kind {
						"text" => if
							field.max_length >= 1 and field.max_length <= 1000 and field.choices.is_empty()
							[]
						else
							[{ field: location, code: "invalid_text_limit" }]
						"integer"
						| "boolean" => if
							field.max_length == 0 and field.choices.is_empty()
							[]
						else
							[{ field: location, code: "invalid_field_options" }]
						"enum" => {
							bounds =
								if
									field.max_length == 0 and !field.choices.is_empty() and field.choices.len() <= 50
									[]
								else
									[{ field: location, code: "invalid_enum_choices" }]
							duplicate =
								if
									field.choices.any(|choice| field.choices.keep_if(|other| other == choice).len() > 1)
									[{ field: location, code: "duplicate_enum_choice" }]
								else
									[]
							bad =
								if
									field.choices.any(|choice| choice.trim().is_empty() or length(choice) > 100)
									[{ field: location, code: "invalid_enum_choice" }]
								else
									[]
							bounds.concat(duplicate).concat(bad)
						}
						_ => [{ field: location, code: "invalid_field_type" }]
					}
					findings.concat(name).concat(type_findings)
				},
			),
		)
	}

	validate_template : List(Field), Str -> List(Finding)
	validate_template = |fields, template| {
		if template.trim().is_empty() {
			[{ field: "template", code: "required" }]
		} else if length(template) > 3000 {
			[{ field: "template", code: "too_long" }]
		} else {
			match segments(template) {
				Err(_) => [{ field: "template", code: "invalid_placeholder" }]
				Ok(parts) => if
					parts.any(|part| !part.name.is_empty() and !fields.any(|field| field.name == part.name))
					[{ field: "template", code: "unknown_placeholder" }]
				else
					[]
			}
		}
	}

	validate_configuration : Str, Str, List(Field), Str -> List(Finding)
	validate_configuration = |event_key, description, fields, template| {
		key = if valid_event_key(event_key) [] else [{ field: "event_key", code: "invalid_event_key" }]
		desc =
			if
				description.trim().is_empty()
				[{ field: "description", code: "required" }]
			else
				if length(description) > 500 [{ field: "description", code: "too_long" }] else []
		key.concat(desc).concat(validate_schema(fields)).concat(validate_template(fields, template))
	}

	validate_payload : List(Field), List(Value) -> List(Finding)
	validate_payload = |fields, payload| {
		if payload.len() > 20 {
			return [{ field: "payload", code: "too_many_fields" }]
		}
		duplicates =
			if
				payload.any(|value| payload.keep_if(|other| other.name == value.name).len() > 1)
				[{ field: "payload", code: "duplicate_field" }]
			else
				[]
		unknown = payload.keep_if(|value| !fields.any(|field| field.name == value.name)).map(
			|value| {
				field: if valid_field_name(value.name) value.name else "payload",
				code: "undeclared_field",
			},
		)
		duplicates.concat(unknown).concat(
			fields.fold(
				[],
				|findings, field| {
					code = match payload.find_first(|value| value.name == field.name) {
						Err(_) => "required"
						Ok(value) => if field.kind == "text" and value.kind == "text" {
							if length(value.text) <= field.max_length "" else "too_long"
						} else if field.kind == "enum" and value.kind == "text" {
							if field.choices.any(|choice| choice == value.text) "" else "invalid_enum_choice"
						} else if (field.kind == "integer" or field.kind == "boolean") and field.kind == value.kind {
							""
						} else {
							"wrong_type"
						}
					}
					if code.is_empty() findings else findings.append({ field: field.name, code })
				},
			),
		)
	}

	render : List(Field), Str, List(Value) -> { valid : Bool, message : Str, findings : List(Finding) }
	render = |fields, template, payload| {
		schema_findings = validate_schema(fields)
		if !schema_findings.is_empty() {
			return { valid: Bool.False, message: "", findings: schema_findings }
		}
		findings = validate_template(fields, template).concat(validate_payload(fields, payload))
		if !findings.is_empty() {
			{ valid: Bool.False, message: "", findings }
		} else {
			match segments(template) {
				Err(_) => {
					valid: Bool.False,
					message: "",
					findings: [{ field: "template", code: "invalid_placeholder" }],
				}
				Ok(parts) => {
					message = Str.join_with(
						parts.map(
							|part| if part.name.is_empty() part.text else {
								match payload.find_first(|value| value.name == part.name) {
									Err(_) => ""
									Ok(value) => match value.kind {
										"integer" => value.integer.to_str()
										"boolean" => if value.boolean "true" else "false"
										_ => value.text
									}
								}
							},
						),
						"",
					)
					if length(message) > 3000 {
						{
							valid: Bool.False,
							message: "",
							findings: [{ field: "template", code: "rendered_message_too_long" }],
						}
					} else {
						{ valid: Bool.True, message, findings: [] }
					}
				}
			}
		}
	}

	summary_fields : List(Field)
	summary_fields = [{ name: "summary", kind: "text", max_length: 1000, choices: [] }]
}

alphanumeric : U8 -> Bool
alphanumeric = |byte| (byte >= 97 and byte <= 122) or (byte >= 48 and byte <= 57)

identifier : Str, U64, Bool -> Bool
identifier = |value, maximum, event| {
	bytes = value.to_utf8()
	!bytes.is_empty() and bytes.len() <= maximum
		and (match bytes.first() {
			Ok(byte) => byte >= 97 and byte <= 122
			Err(_) => Bool.False
		})
			and bytes.all(|byte| alphanumeric(byte) or byte == 95 or (event and (byte == 46 or byte == 45)))
}

# Each part is either literal text or a validated name. Inserted payload text
# never passes through this parser and therefore cannot create another placeholder.
segments : Str -> Try(List({ name : Str, text : Str }), Str)
segments = |template| {
	match template.split_on("{{") {
		[] => Ok([])
		[first, .. as rest] => {
			if first.contains("}}") {
				return Err("invalid_placeholder")
			}
			parts = rest.map_try(
				|part| match part.split_on("}}") {
					[name, literal] => {
						if !NotificationRules.valid_field_name(name) {
							return Err("invalid_placeholder")
						}
						Ok([{ name, text: "" }, { name: "", text: literal }])
					}
					_ => Err("invalid_placeholder")
				},
			)?
			Ok(parts.fold([{ name: "", text: first }], |all, part| all.concat(part)))
		}
	}
}
