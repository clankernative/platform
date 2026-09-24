import Models

Storage :: [].{
	Tables : { things : List(Models.Thing) }

	schema : Tables -> Tables
	schema = |tables| tables

	definition = { schema, identities: "model-identities.json", domains: {} }
}
