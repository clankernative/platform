import pf.Table

Models :: [].{
	Link := { name : Str, url : Str, visits : U64, deleted : Bool }.{
		table : Table(Link, _)
		table = Table.keyed(|row| { by_name: Table.unique({ name: row.name }) })
	}
}
