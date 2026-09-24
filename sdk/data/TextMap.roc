# A keyed collection with unique, nonblank text keys. The representation is a list
# of pairs because the reflection exposes records and lists only; the contract is a
# map. Key uniqueness is a constructor invariant, so an application never rejects
# duplicate keys itself. Entries are canonically ordered by key, so one map has
# exactly one encoding and two orderings cannot denote the same value.
#
# Named TextMap rather than Map because Map shadows a Roc builtin.
TextMap(value) :: { entries : List({ key : Str, value : value }) }.{
	empty : TextMap(value)
	empty = { entries: [] }

	from_entries : List({ key : Str, value : value }) -> Try(TextMap(value), [DuplicateKey, BlankKey])
	from_entries = |raw| {
		if raw.any(|entry| entry.key.trim().is_empty()) {
			return Err(BlankKey)
		}
		if repeated(raw.map(|entry| entry.key)) {
			return Err(DuplicateKey)
		}
		Ok({ entries: raw.sort_with(|left, right| order_bytes(left.key.to_utf8(), right.key.to_utf8())) })
	}

	to_entries : TextMap(value) -> List({ key : Str, value : value })
	to_entries = |map| map.entries

	get : TextMap(value), Str -> [None, Some(value)]
	get = |map, key| match map.entries.find_first(|entry| entry.key == key) {
		Err(_) => None
		Ok(entry) => Some(entry.value)
	}

	keys : TextMap(value) -> List(Str)
	keys = |map| map.entries.map(|entry| entry.key)

	len : TextMap(value) -> U64
	len = |map| map.entries.len()

	is_empty : TextMap(value) -> Bool
	is_empty = |map| map.entries.is_empty()
}

repeated : List(Str) -> Bool
repeated = |keys| match keys {
	[] => Bool.False
	[first, .. as rest] => rest.any(|key| key == first) or repeated(rest)
}

order_bytes : List(U8), List(U8) -> [Before, Same, After]
order_bytes = |left, right| match (left, right) {
	([], []) => Same
	([], _) => Before
	(_, []) => After
	([a, .. as rest_a], [b, .. as rest_b]) =>
		if a < b Before else if a > b After else order_bytes(rest_a, rest_b)
	}
