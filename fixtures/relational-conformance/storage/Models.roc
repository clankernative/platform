import pf.Ref
import pf.Text
import Title

Models :: [].{
	Stage := { name : Str, deal_count : I64 }

	Deal := { title : Text(Title), stage_id : Ref(Stage) }

	History := { deal_id : Ref(Deal), from_stage_id : Ref(Stage), to_stage_id : Ref(Stage), occurred_at : I64 }
}
