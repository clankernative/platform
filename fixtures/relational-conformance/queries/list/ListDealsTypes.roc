import pf.Ref
import pf.Cursor
import pf.PageSize
import Models

ListDealsTypes :: [].{
	Input := { stage_id : Ref(Models.Stage), after : Cursor, limit : PageSize }
}
