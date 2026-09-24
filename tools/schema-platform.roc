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

domain_shape = |_| domains

storage = SchemaSource.storage

storage_shape = |_| storage
