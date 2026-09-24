import pf.Model
import pf.Ref
import pf.RowVersion
import pf.Text
import pf.CollectionPage
import Models
import Title
import Domains

DealView :: [].{
	Value : { id : Ref(Models.Deal), version : RowVersion, title : Text(Title), stage_id : Ref(Models.Stage) }

	Page : CollectionPage(Value)

	Saved : { id : Ref(Models.Deal), version : RowVersion }

	Seeded : { deal_id : Ref(Models.Deal), source_stage_id : Ref(Models.Stage), target_stage_id : Ref(Models.Stage) }

	fields = {
		id: "The deal identifier.",
		version: "The current revision.",
		title: "The deal title.",
		stage_id: "The current stage identifier.",
	}

	saved_fields = { id: "The moved deal identifier.", version: "The new revision." }

	seeded_fields = {
		deal_id: "The created deal identifier.",
		source_stage_id: "The initial stage identifier.",
		target_stage_id: "The other stage identifier.",
	}

	example : {} -> Try(Value, Str)
	example = |_| {
		id = Ref.from_str("dea_0000000000e008000000000000").map_err(|_| "invalid deal example")?
		stage_id = Ref.from_str("sta_0000000000e008000000000000").map_err(|_| "invalid stage example")?
		title = Domains.title("Example deal")?
		Ok({ id, version: RowVersion.one, title, stage_id })
	}

	from_row : Model.Entity(Models.Deal) -> Value
	from_row = |row| { id: row.id, version: row.version, title: row.value.title, stage_id: row.value.stage_id }
}
