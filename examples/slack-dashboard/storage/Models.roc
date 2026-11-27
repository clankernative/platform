import pf.Table

Models :: [].{
	Revision := { number : U64, html : Str, author : Str }.{
		table : Table(Revision, _)
		table = Table.keyed(|row| { by_number: Table.unique({ number: row.number }) })
	}
}
