Index :: [].{
	# The pinned native compiler can alias three or more zero-sized record
	# fields. This nonzero witness keeps every declared field label distinct.
	Field := { witness : List({}) }

	field : Field
	field = { witness: [] }

	# Closed tags and list witnesses preserve field labels in native reflection,
	# including declarations whose runtime witness lists are empty.
	unique : fields -> [Unique(List(fields))]
	unique = |_fields| Unique([])

	non_unique : fields -> [NonUnique(List(fields))]
	non_unique = |_fields| NonUnique([])
}
