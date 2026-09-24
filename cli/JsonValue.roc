## Bounded JSON syntax gate. Keeps object entries until duplicate decoded keys
## have been rejected, including escape-equivalent keys in ignored metadata.
JsonValue := [Object(List((Str, JsonValue))), Array(List(JsonValue)), String(Str), Number(Str), Boolean(Bool), Null].{
	parse : Str -> Try(JsonValue, [BadJson(Str)])
	parse = |raw| {
		if raw.count_utf8_bytes() > 1_048_576 {
			return Err(BadJson("document exceeds 1 MiB"))
		}
		parsed = value(raw.to_utf8(), 0, 0)?
		if !whitespace(parsed.rest).is_empty() {
			return Err(BadJson("trailing content"))
		}
		Ok(parsed.node)
	}

	object : JsonValue -> Try(List((Str, JsonValue)), [BadJson(Str)])
	object = |node| match node {
		Object(pairs) => Ok(pairs)
		_ => Err(BadJson("expected an object"))
	}

	array : JsonValue -> Try(List(JsonValue), [BadJson(Str)])
	array = |node| match node {
		Array(items) => Ok(items)
		_ => Err(BadJson("expected an array"))
	}

	string : JsonValue -> Try(Str, [BadJson(Str)])
	string = |node| match node {
		String(text) => Ok(text)
		_ => Err(BadJson("expected a string"))
	}

	u64 : JsonValue -> Try(U64, [BadJson(Str)])
	u64 = |node| match node {
		Number(text) => {
			parsed : Try(U64, [InvalidJson(Str)])
			parsed = Json.parse(text)
			parsed.map_err(|_| BadJson("expected an unsigned integer"))
		}
		_ => Err(BadJson("expected an unsigned integer"))
	}

	get : JsonValue, Str -> Try(JsonValue, [BadJson(Str)])
	get = |node, key| {
		pairs = object(node)?
		match pairs.keep_if(|pair| pair.0 == key).first() {
			Ok(pair) => Ok(pair.1)
			Err(_) => Err(BadJson("missing field ${key}"))
		}
	}

	optional : JsonValue, Str -> Try([Absent, Present(JsonValue)], [BadJson(Str)])
	optional = |node, key| {
		pairs = object(node)?
		match pairs.keep_if(|pair| pair.0 == key).first() {
			Ok(pair) => Ok(Present(pair.1))
			Err(_) => Ok(Absent)
		}
	}

	keys : JsonValue, List(Str) -> Try({}, [BadJson(Str)])
	keys = |node, allowed| {
		pairs = object(node)?
		if
			pairs.all(|pair| allowed.contains(pair.0))
			Ok({})
		else
			Err(BadJson("unknown field in a checked metadata object"))
	}
}

Parsed : { node : JsonValue, rest : List(U8), count : U64 }

whitespace : List(U8) -> List(U8)
whitespace = |bytes| match bytes {
	[byte, .. as rest] if [32, 9, 10, 13].contains(byte) => whitespace(rest)
	_ => bytes
}

value : List(U8), U64, U64 -> Try(Parsed, [BadJson(Str)])
value = |bytes, depth, count| {
	if depth >= 32 or count >= 20_000 {
		return Err(BadJson("JSON nesting or node budget exceeded"))
	}
	match whitespace(bytes) {
		[34, .. as rest] => {
			parsed = string_token(rest, [34], Bool.False)?
			Ok({ node: JsonValue.String(parsed.text), rest: parsed.rest, count: count + 1 })
		}
		[123, .. as rest] => object_start(whitespace(rest), depth + 1, count + 1)
		[91, .. as rest] => array_start(whitespace(rest), depth + 1, count + 1)
		['t', 'r', 'u', 'e', .. as rest] => Ok({ node: JsonValue.Boolean(Bool.True), rest, count: count + 1 })
		['f', 'a', 'l', 's', 'e', .. as rest] => Ok({ node: JsonValue.Boolean(Bool.False), rest, count: count + 1 })
		['n', 'u', 'l', 'l', .. as rest] => Ok({ node: JsonValue.Null, rest, count: count + 1 })
		[byte, ..] as remaining if byte
			== '-'
			or (byte
				>= '0'
				and byte <= '9') ## Bounded JSON syntax gate. Keeps object entries until duplicate decoded keys
		## have been rejected, including escape-equivalent keys in ignored metadata.
			=> number(remaining, [], count)
		_ => Err(BadJson("expected a JSON value"))
	}
}

string_token : List(U8), List(U8), Bool -> Try({ text : Str, rest : List(U8) }, [BadJson(Str)])
string_token = |bytes, token, escaped| match bytes {
	[] => Err(BadJson("unterminated JSON string"))
	[byte, .. as rest] => {
		if byte == 34 and !escaped {
			parsed : Try(Str, [InvalidJson(Str)])
			parsed = Json.parse(Str.from_utf8_lossy(token.append(byte)))
			text = parsed.map_err(|_| BadJson("invalid JSON string or escape"))?
			Ok({ text, rest })
		} else if byte < 32 {
			Err(BadJson("unescaped control character"))
		}
			else {
				string_token(rest, token.append(byte), byte == 92 and !escaped)
			}
	}
}

number : List(U8), List(U8), U64 -> Try(Parsed, [BadJson(Str)])
number = |bytes, token, count| match bytes {
	[byte, .. as rest] if ![32, 9, 10, 13, 44, 93, 125].contains(byte) => number(rest, token.append(byte), count)
	_ => {
		text = Str.from_utf8_lossy(token)
		parsed : Try(F64, [InvalidJson(Str)])
		parsed = Json.parse(text)
		_ = parsed.map_err(|_| BadJson("invalid or out-of-range JSON number"))?
		Ok({ node: JsonValue.Number(text), rest: bytes, count: count + 1 })
	}
}

object_start : List(U8), U64, U64 -> Try(Parsed, [BadJson(Str)])
object_start = |bytes, depth, count| match bytes {
	[125, .. as rest] => Ok({ node: JsonValue.Object([]), rest, count })
	_ => object_member(bytes, depth, count, [], Set.empty())
}

object_member : List(U8), U64, U64, List((Str, JsonValue)), Set(Str) -> Try(Parsed, [BadJson(Str)])
object_member = |bytes, depth, count, pairs, seen| match bytes {
	[34, .. as rest] => {
		key = string_token(rest, [34], Bool.False)?
		if seen.contains(key.text) {
			return Err(BadJson("duplicate object key"))
		}
		match whitespace(key.rest) {
			[58, .. as content] => {
				parsed = value(content, depth, count)?
				next = pairs.append((key.text, parsed.node))
				match whitespace(parsed.rest) {
					[125, .. as tail] => Ok({ node: JsonValue.Object(next), rest: tail, count: parsed.count })
					[44, .. as tail] => object_member(
						whitespace(tail),
						depth,
						parsed.count,
						next,
						seen.insert(key.text),
					)
					_ => Err(BadJson("expected comma or closing object brace"))
				}
			}
			_ => Err(BadJson("expected colon after object key"))
		}
	}
	_ => Err(BadJson("expected a quoted object key"))
}

array_start : List(U8), U64, U64 -> Try(Parsed, [BadJson(Str)])
array_start = |bytes, depth, count| match bytes {
	[93, .. as rest] => Ok({ node: JsonValue.Array([]), rest, count })
	_ => array_member(bytes, depth, count, [])
}

array_member : List(U8), U64, U64, List(JsonValue) -> Try(Parsed, [BadJson(Str)])
array_member = |bytes, depth, count, items| {
	parsed = value(bytes, depth, count)?
	next = items.append(parsed.node)
	match whitespace(parsed.rest) {
		[93, .. as rest] => Ok({ node: JsonValue.Array(next), rest, count: parsed.count })
		[44, .. as rest] => array_member(whitespace(rest), depth, parsed.count, next)
		_ => Err(BadJson("expected comma or closing array bracket"))
	}
}

expect match JsonValue.parse("{\"name\":1,\"na\\u006de\":2}") {
	Err(_) => Bool.True
	Ok(_) => Bool.False
}
expect match JsonValue.parse("{\"ignored\":{\"x\":true,\"x\":false}}") {
	Err(_) => Bool.True
	Ok(_) => Bool.False
}
expect match JsonValue.parse("[1,]") {
	Err(_) => Bool.True
	Ok(_) => Bool.False
}
expect match JsonValue.parse("{\"x\":[true,null,\"hello\\nworld\",1.25e2]}") {
	Ok(_) => Bool.True
	Err(_) => Bool.False
}
