import pf.Table

# Persistent samples are actor-owned and nominal. UTC timestamps are epoch milliseconds.
Models :: [].{
	ChartSample := {
		owner : Str,
		time : I64,
		value : I64,
		missing : Bool,
	}.{
		is_eq : ChartSample, ChartSample -> Bool
		is_eq = |left, right| [
			left.owner == right.owner,
			left.time == right.time,
			left.value == right.value,
			left.missing == right.missing,
		].all(|equal| equal)

		table : Table(ChartSample, _)
		table = Table.keyed(
			|row| {
				by_owner: Table.non_unique({ owner: row.owner }),
				by_owner_time: Table.unique({ owner: row.owner, time: row.time }),
			},
		)
	}
}
