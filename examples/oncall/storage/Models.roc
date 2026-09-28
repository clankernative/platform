import pf.Table

Models :: [].{
	Incident := {
		title : Str,
		status : Str,
		rung : I64,
	}.{
		table : Table(Incident, _)
		table = Table.keyed(|_| {})
	}
}
