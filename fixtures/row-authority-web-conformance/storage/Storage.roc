import Models
import Title

Storage :: [].{
	Tables : { links : List(Models.Link) }

	schema : Tables -> Tables
	schema = |tables| tables

	definition = { schema, identities: "model-identities.json", domains: { title: Title.rules } }
}
