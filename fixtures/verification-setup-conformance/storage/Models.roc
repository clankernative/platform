import pf.Table

Models :: [].{
	ActorState := { actor : Str, stage : U64, fail_second : Bool }.{
		table : Table(ActorState, _)
		table = Table.keyed(|row| { by_actor: Table.non_unique({ actor: row.actor }) })
	}
}
