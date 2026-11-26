import pf.Example
import Commands

Demo :: [].{
	definition = Example.define(
		"first_revision",
		Ok([
			Example.Step.command(Commands.save_revision, { html: "<h1>Channel activity</h1>" }),
		]),
	)
}
