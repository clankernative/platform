import pf.Example
import Commands

Demo :: [].{
	definition = Example.define(
		"demo",
		Ok([
			Example.Step.command(Commands.create, { name: "docs", url: "https://example.com/docs" }),
			Example.Step.command(Commands.create, { name: "team", url: "https://example.com/team" }),
			Example.Step.command(Commands.create, { name: "docs/%s", url: "https://example.com/search?q=%s" }),
			Example.Step.command(Commands.create, { name: "codex", url: "codex://session/open?id=abc123" }),
			Example.Step.command(Commands.visit, { path: "docs" }),
		]),
	)
}
