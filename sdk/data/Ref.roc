# A typed public identifier; neither existence nor authorization is implied.
Ref(a) :: { value : Str, witness : List(a) }.{
	from_str : Str -> Try(Ref(a), [InvalidRef])
	from_str = |raw| {
		parts = raw.split_on("_")
		if parts.len() != 2 {
			return Err(InvalidRef)
		}
		prefix = parts.get(0).map_err(|_| InvalidRef)?
		suffix = parts.get(1).map_err(|_| InvalidRef)?
		prefix_bytes = prefix.to_utf8()
		bytes = suffix.to_utf8()
		if prefix_bytes.len() < 3 or prefix_bytes.len() > 63 or bytes.len() != 26 {
			return Err(InvalidRef)
		}
		if !prefix_bytes.all(|byte| byte >= 97 and byte <= 122) {
			return Err(InvalidRef)
		}
		alphabet = "0123456789abcdefghjkmnpqrstvwxyz".to_utf8()
		if !bytes.all(|byte| alphabet.contains(byte)) {
			return Err(InvalidRef)
		}
		first = bytes.get(0).map_err(|_| InvalidRef)?
		version = bytes.get(10).map_err(|_| InvalidRef)?
		variant = bytes.get(13).map_err(|_| InvalidRef)?
		if first > 55 or (version != 101 and version != 102) or !"89abrstv".to_utf8().contains(variant) {
			return Err(InvalidRef)
		}
		Ok({ value: raw, witness: [] })
	}

	for_model : Str, Str -> Try(Ref(a), [InvalidRef])
	for_model = |prefix, raw| {
		ref = from_str(raw)?
		if raw.starts_with("${prefix}_") and raw.count_utf8_bytes() == prefix.count_utf8_bytes() + 27 {
			Ok(ref)
		} else {
			Err(InvalidRef)
		}
	}

	to_str : Ref(a) -> Str
	to_str = |ref| ref.value

	is_eq : Ref(a), Ref(a) -> Bool
	is_eq = |left, right| left.value == right.value
}
