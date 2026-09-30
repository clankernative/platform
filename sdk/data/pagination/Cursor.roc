import Ref

# Empty starts traversal. Legacy pages carry an identifier; ordered selections
# carry an opaque keyset token. The host validates the token against the query.
# Neither form freezes the database between requests.
Cursor :: { value : Str }.{
	start : Cursor
	start = { value: "" }

	from_str : Str -> Try(Cursor, [InvalidCursor])
	from_str = |raw| {
		if raw.is_empty() {
			return Ok(start)
		}
		if raw.starts_with("cm1_") {
			bytes = raw.to_utf8()
			if
				bytes.len()
					<= 4
					or bytes.len()
						> 2200
						or !bytes
							.drop_first(4)
							.all(
								|
									byte,
								|
									(byte >= 48 and byte <= 57)
										or (byte >= 65 and byte <= 90)
											or (byte >= 97 and byte <= 122) or byte == 95 or byte == 45,
							)
					{
						return Err(InvalidCursor)
					}
			return Ok({ value: raw })
		}
		if raw.starts_with("sel1_") {
			bytes = raw.to_utf8()
			if bytes.len() != 69 {
				return Err(InvalidCursor)
			}
			if !bytes.drop_first(5).all(|byte| (byte >= 48 and byte <= 57) or (byte >= 97 and byte <= 102)) {
				return Err(InvalidCursor)
			}
			return Ok({ value: raw })
		}
		ref : Try(Ref({}), [InvalidRef])
		ref = Ref.from_str(raw)
		_ = ref.map_err(|_| InvalidCursor)?
		Ok({ value: raw })
	}

	to_str : Cursor -> Str
	to_str = |cursor| cursor.value

	is_start : Cursor -> Bool
	is_start = |cursor| cursor.value.is_empty()

	is_eq : Cursor, Cursor -> Bool
	is_eq = |left, right| left.value == right.value
}
