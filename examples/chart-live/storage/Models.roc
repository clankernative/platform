import pf.Table

# Persistent samples are actor-owned and nominal. UTC timestamps are epoch milliseconds.
Models :: [].{
	ChartSample := {
		owner : Str,
		time : I64,
		value : I64,
		missing : Bool,
	}.{
		table : Table(ChartSample, _)
		table = Table.keyed(
			|row| {
				by_owner: Table.non_unique({ owner: row.owner }),
				by_owner_time: Table.unique({ owner: row.owner, time: row.time }),
			},
		)
	}
}
