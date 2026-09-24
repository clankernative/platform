platform "day2-app-shape"
	requires {
		unused : {} -> {}
	}
	exposes []
	packages { pf: "../sdk/types.roc" }
	provides {
		"day2_schema": schema_shape,
		"day2_domains": domain_shape,
		"day2_storage": storage_shape,
		"day2_app": app_shape,
	}
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

import App
import StorageContract
import pf.Context
import pf.Model
import pf.Tx
import pf.Query
import pf.Api

schema_shape : StorageContract.Tables -> StorageContract.Tables
schema_shape = |value| (App.definition.storage.schema)(value)

# The checked wrappers carry native type witnesses for callback inputs/results.
# Include named properties and errors so glue commits their complete layouts.
# The final generated dispatcher checks the exact root, including presentation.
# A module constant gives the native glue API a committed record layout.
shape =
	{
		namespace: App.definition.namespace,
		operations: App.definition.operations,
		pages: App.definition.pages,
		properties: App.definition.properties,
		errors: App.definition.errors,

	}

app_shape = |_| shape

domains = App.definition.storage.domains

domain_shape = |_| domains

storage = App.definition.storage

storage_shape = |_| storage

command_input : Api.CommandDef(input, output, inputs, outputs), input -> input
command_input = |_handler, value| value

command_output : Api.CommandDef(input, output, inputs, outputs), output -> output
command_output = |_handler, value| value

query_input : Api.QueryDef(input, output, inputs, outputs), input -> input
query_input = |_handler, value| value

query_output : Api.QueryDef(input, output, inputs, outputs), output -> output
query_output = |_handler, value| value
