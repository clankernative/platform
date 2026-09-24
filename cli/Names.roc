## Opaque boundary values. No parser/encoder derivation may bypass constructors.
Names :: [].{
	App :: Str.{
		from_str : Str -> Try(App, [InvalidName])
		from_str = |value| if valid_identifier(value) Ok(App.(value)) else Err(InvalidName)

		to_str : App -> Str
		to_str = |App.(value)| value
	}

	Identifier :: Str.{
		from_str : Str -> Try(Identifier, [InvalidName])
		from_str = |value| if valid_identifier(value) Ok(Identifier.(value)) else Err(InvalidName)

		to_str : Identifier -> Str
		to_str = |Identifier.(value)| value
	}

	Operation :: Str.{
		from_str : Str -> Try(Operation, [InvalidName])
		from_str =
			|
				value,
			|
				if
					value.count_utf8_bytes() <= 80 and value.split_on(".").all(valid_identifier)
					Ok(Operation.(value))
				else
					Err(InvalidName)

		to_str : Operation -> Str
		to_str = |Operation.(value)| value
	}

	RocType :: Str.{
		from_str : Str -> Try(RocType, [InvalidName])
		from_str =
			|
				value,
			|
				if
					value.count_utf8_bytes() <= 128 and value.split_on(".").all(valid_type_part)
					Ok(RocType.(value))
				else
					Err(InvalidName)

		to_str : RocType -> Str
		to_str = |RocType.(value)| value
	}

	LocalPath :: Str.{
		from_str : Str -> Try(LocalPath, [InvalidPath])
		from_str =
			|
				value,
			|
				if
					!value.trim().is_empty()
						and value.count_utf8_bytes() <= 4096 and value.to_utf8().all(|byte| byte >= 32 and byte != 127)
					Ok(LocalPath.(value))
				else
					Err(InvalidPath)

		to_str : LocalPath -> Str
		to_str = |LocalPath.(value)| value
	}

	order : Str, Str -> [Before, Same, After]
	order = |a, b| order_bytes(a.to_utf8(), b.to_utf8())
}

valid_identifier : Str -> Bool
valid_identifier = |value| {
	bytes = value.to_utf8()
	match bytes {
		[first, ..] => bytes.len()
			<= 48
			and first
				>= 'a'
				and first
					<= 'z'
					and !value.starts_with("day2_")
						and !value.starts_with("sqlite_")
							and bytes
								.all(
									|
										byte,
									| (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '_',
								)
		[] => Bool.False
	}
}

valid_type_part : Str -> Bool
valid_type_part = |value| match value.to_utf8() {
	[first, .. as rest] => first
		>= 'A'
		and first
			<= 'Z'
			and rest
				.all(
					|
						byte,
					|
						(byte >= 'a' and byte <= 'z')
							or (byte >= 'A' and byte <= 'Z') or (byte >= '0' and byte <= '9') or byte == '_',
				)
	[] => Bool.False
}

order_bytes : List(U8), List(U8) -> [Before, Same, After]
order_bytes = |a, b| match (a, b) {
	([], []) => Same
	([], _) => Before
	(_, []) => After
	([x, .. as xs], [y, .. as ys]) => if x < y Before else if x > y After else order_bytes(xs, ys)
}

expect match Names.App.from_str("") {
	Err(InvalidName) => Bool.True
	_ => Bool.False
}
expect match Names.Identifier.from_str("sqlite_table") {
	Err(InvalidName) => Bool.True
	_ => Bool.False
}
expect match Names.Operation.from_str("links..list") {
	Err(InvalidName) => Bool.True
	_ => Bool.False
}
expect match Names.Operation.from_str("links.list") {
	Ok(value) => value.to_str() == "links.list"
	Err(_) => Bool.False
}
