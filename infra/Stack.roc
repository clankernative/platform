# Pure, platform-owned descriptions. The first qualified subset uses OpenTofu's
# built-in terraform_data provider; cloud resources can extend this same graph.
Stack :: [].{
	Settings : { installation : Str, environment : Str, apps : List(Str), configuration_digest : Str }

	Input : { name : Str, kind : Str, value : Str, target : Str, attribute : Str }

	Resource : { key : Str, inputs : List(Input) }

	Graph : { format : U32, resources : List(Resource) }

	graph : Settings -> Graph
	graph = |settings| {
		format: 1,
		resources: [
			{
				key: "scope",
				inputs: [literal("installation", settings.installation), literal("environment", settings.environment)],
			},
		]
			.concat(
				settings
					.apps
					.map(
						|
							app_name,
						|
							{
								key: "app_${app_name}",
								inputs: [
									literal("name", app_name),
									{
										name: "scope",
										kind: "reference",
										value: "",
										target: "scope",
										attribute: "output",
									},
								],
							},
					),
			),
	}

	literal : Str, Str -> Input
	literal = |name, value| { name, kind: "literal", value, target: "", attribute: "" }
}

expect Stack.graph(
	{ installation: "exampleco", environment: "sandbox", apps: ["reports"], configuration_digest: "test" },
)
	.resources
	.len()
	== 2
