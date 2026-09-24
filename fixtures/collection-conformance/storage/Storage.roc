import Models
import pf.Index

Storage :: [].{
	Tables : { entries : List(Models.Entry) }

	schema : Tables -> Tables
	schema = |tables| tables

	definition = {
		schema,
		identities: "model-identities.json",
		domains: {},
		indexes: { entries: { by_bucket_rank: Index.non_unique({ bucket: Index.field, rank: Index.field }) } },
	}
}
