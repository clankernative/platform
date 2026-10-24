BatchUpdateEntriesTypes :: [].{
	Change : { id : Str, version : U64, note : Str }

	Input := { changes : List(Change) }
}
