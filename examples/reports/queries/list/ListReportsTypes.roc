import pf.Cursor
import pf.PageSize

ListReportsTypes :: [].{
	Input := { after : Cursor, limit : PageSize }
}
