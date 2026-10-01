import pf.Table

Models :: [].{
	Reservation := { owner : Str, quantity : U64 }.{
		table : Table(Reservation, _)
		table = Table.keyed(|row| { by_owner: Table.non_unique({ owner: row.owner }) })
	}
}
