import Models

Storage :: [].{
	Tables : { entries : List(Models.Entry) }

	schema : Tables -> Tables
	schema = |tables| tables

	definition = { schema, identities: "model-identities.json", domains: {} }
}
