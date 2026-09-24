# Generated, closed application failure identities. Description and recovery are
# required at App.definition.errors; public code cannot invent arbitrary strings.
Failure :: { code : Str }.{
	define : Str -> Failure
	define = |name| { code: "app:${name}" }

	code : Failure -> Str
	code = |failure| failure.code
}
