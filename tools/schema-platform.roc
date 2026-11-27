platform "day2-schema"
	requires {
		unused : {} -> {}
	}
	exposes []
	packages { pf: "../sdk/types.roc" }
	provides { "day2_schema": schema_shape, "day2_domains": domain_shape, "day2_storage": storage_shape }
	targets: {
		inputs_dir: "targets/",
		arm64mac: { inputs: ["libhost.a", app] },
		arm64glibc: {
			inputs: [app],
			output: Archive,
		},
		x64glibc: {
			inputs: [app],
			output: Archive,
		},
	}

import SchemaSource

schema_shape = SchemaSource.schema

domains = SchemaSource.domains

domain_shape = |{}| domains

storage = SchemaSource.storage

# Glue requires a determined argument type and boxed functions in host-visible
# values. The witness record holds functions, so it is returned in a Box.
storage_shape = |{}| Box.box(storage)
