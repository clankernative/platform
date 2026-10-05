import pf.Example
import Commands
import NotificationRules

Demo :: [].{
	definition = Example.define(
		"publication",
		Ok([
			Example.Step.command(
				Commands.save,
				{
					app_id: "demo",
					event_key: "build.completed",
					description: "A build completed.",
					expected_revision: 0,
					version: 0,
					fields: NotificationRules.summary_fields,
					template: "Build: {{summary}}",
				},
			),
			Example.Step.command(
				Commands.set_enabled,
				{
					app_id: "demo",
					event_key: "build.completed",
					expected_revision: 1,
					enabled: Bool.True,
				},
			),
			Example.Step.command(
				Commands.publish,
				{
					app_id: "demo",
					event_key: "build.completed",
					version: 1,
					publication_id: "example-build",
					payload: [{ name: "summary", kind: "text", text: "passed", integer: 0, boolean: Bool.False }],
				},
			),
		]),
	)
}
