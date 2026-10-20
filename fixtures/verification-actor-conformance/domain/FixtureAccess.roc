# This is a toy fixture permission rule, not production authentication.
# The platform's disposable fixture operator is the only authorized actor.
FixtureAccess :: [].{
	authorized : Str -> Bool
	authorized = |actor| actor == "developer"
}
