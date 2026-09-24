# Validated result count, from 1 through 100. It is not a query-planner guarantee.
PageSize :: { value : I64 }.{
	one : PageSize
	one = { value: 1 }

	default : PageSize
	default = { value: 20 }

	maximum : PageSize
	maximum = { value: 100 }

	from_i64 : I64 -> Try(PageSize, [InvalidPageSize])
	from_i64 = |number| if number >= 1 and number <= 100 {
		Ok({ value: number })
	} else {
		Err(InvalidPageSize)
	}

	to_i64 : PageSize -> I64
	to_i64 = |size| size.value

	is_eq : PageSize, PageSize -> Bool
	is_eq = |left, right| left.value == right.value
}
