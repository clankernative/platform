import pf.Ref
import pf.Cursor
import Models

UpdateCollectEntriesTypes :: [].{
	Input := { row_id : Ref(Models.Entry), bucket : Str, maximum_rows : U64, after : Cursor, note : Str }
}
