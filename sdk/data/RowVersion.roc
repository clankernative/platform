# A host row revision: positive and representable by SQLite's signed integer.
RowVersion :: { value : U64 }.{
	one : RowVersion
	one = { value: 1 }

	from_u64 : U64 -> Try(RowVersion, [InvalidRowVersion])
	from_u64 = |number| if number >= 1 and number <= 9_223_372_036_854_775_807 {
		Ok({ value: number })
	} else {
		Err(InvalidRowVersion)
	}

	from_i64 : I64 -> Try(RowVersion, [InvalidRowVersion])
	from_i64 = |number| {
		unsigned = number.to_u64_try().map_err(|_| InvalidRowVersion)?
		from_u64(unsigned)
	}

	to_u64 : RowVersion -> U64
	to_u64 = |version| version.value

	# Private storage instructions use I64; construction checked this upper bound.
	to_i64 : RowVersion -> I64
	to_i64 = |version| match version.value.to_i64_try() {
		Ok(number) => number
		Err(_) => crash "invalid_row_version"
	}

	is_eq : RowVersion, RowVersion -> Bool
	is_eq = |left, right| left.value == right.value
}
