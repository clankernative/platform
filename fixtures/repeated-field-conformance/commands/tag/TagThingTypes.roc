import pf.TextMap
import pf.TextSet

TagThingTypes :: [].{
	# Three distinct collection shapes: tags is ordered with meaningful position,
	# attributes is keyed, groups is unordered and unique.
	Input := { name : Str, tags : List(Str), attributes : TextMap(Str), groups : TextSet }
}
