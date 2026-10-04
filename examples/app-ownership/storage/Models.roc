import pf.Table

Models :: [].{
	Ownership := { app_id : Str, principal : Str, active : Bool }.{
		table : Table(Ownership, _)
		table = Table.keyed(|row| { by_app_principal: Table.unique({ app_id: row.app_id, principal: row.principal }) })
	}
}
