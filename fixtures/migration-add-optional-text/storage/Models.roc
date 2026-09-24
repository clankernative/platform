import pf.Ref
import pf.Text
import Title
import pf.Table

Models :: [].{
	Stage := { name : Str, deal_count : I64 }.{
		table : Table(Stage, _)
		table = Table.keyed(
			|row| {
				by_name: Table.unique({ name: row.name }),
			},
		)
	}

	Deal := { title : Text(Title), stage_id : Ref(Stage), note : [None, Some(Str)] }.{
		table : Table(Deal, _)
		table = Table.keyed(
			|row| {
				by_stage_title: Table.unique({ stage_id: row.stage_id, title: row.title }),
			},
		)
	}

	History := { deal_id : Ref(Deal), from_stage_id : Ref(Stage), to_stage_id : Ref(Stage), occurred_at : I64 }.{
		table : Table(History, _)
		table = Table.keyed(
			|row| {
				by_time: Table.non_unique({
					deal_id: row.deal_id,
					from_stage_id: row.from_stage_id,
					occurred_at: row.occurred_at,
					to_stage_id: row.to_stage_id,
				}),
			},
		)
	}
}
