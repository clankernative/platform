import pf.Table
Models :: [].{
	Entry := { owner : Str, bucket : Str, rank : I64, note : Str }.{
		table : Table(Entry, _)
		table = Table.keyed(
			|row| {
				by_bucket_rank: Table.non_unique({ bucket: row.bucket, rank: row.rank }),
			},
		)
	}
}
