# An unordered collection of unique text members. The representation is a list
# because the reflection exposes records and lists only; the contract is a set.
# Members are canonically ordered, so one set has exactly one encoding and no two
# orderings denote the same value. Duplicates are rejected rather than silently
# collapsed: an interface that accepts a duplicate and discards it cannot tell the
# caller their input was not what they meant.
#
# Named TextSet rather than Set because Set shadows a Roc builtin.
TextSet :: { members : List(Str) }.{
	empty : TextSet
	empty = { members: [] }

	from_list : List(Str) -> Try(TextSet, [DuplicateMember, BlankMember])
	from_list = |raw| {
		if raw.any(|member| member.trim().is_empty()) {
			return Err(BlankMember)
		}
		if repeated(raw) {
			return Err(DuplicateMember)
		}
		Ok({ members: raw.sort_with(|left, right| order_bytes(left.to_utf8(), right.to_utf8())) })
	}

	to_list : TextSet -> List(Str)
	to_list = |set| set.members

	contains : TextSet, Str -> Bool
	contains = |set, member| set.members.any(|value| value == member)

	len : TextSet -> U64
	len = |set| set.members.len()

	is_empty : TextSet -> Bool
	is_empty = |set| set.members.is_empty()
}

repeated : List(Str) -> Bool
repeated = |members| match members {
	[] => Bool.False
	[first, .. as rest] => rest.any(|member| member == first) or repeated(rest)
}

order_bytes : List(U8), List(U8) -> [Before, Same, After]
order_bytes = |left, right| match (left, right) {
	([], []) => Same
	([], _) => Before
	(_, []) => After
	([a, .. as rest_a], [b, .. as rest_b]) =>
		if a < b Before else if a > b After else order_bytes(rest_a, rest_b)
	}
