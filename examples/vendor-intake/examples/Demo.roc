import pf.Example
import Commands
import IntakePolicy

Demo :: [].{
	definition =
		Example.define(
			"synthetic_intake",
			Ok([
				Example.Step.command(Commands.configure, IntakePolicy.example({})),
				Example.Step.command(Commands.save_revision, { html: "<h1>Vendor intake</h1>" }),
			]),
		)
}
