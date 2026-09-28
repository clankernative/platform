import pf.Example
import Commands
import Domains

Demo :: [].{
	definition : Example
	definition = Example.define("demo", steps({}))

	steps : {} -> Try(List(Example.Step), Str)
	steps = |_| {
		weekly = Domains.title("Weekly report")?
		release = Domains.title("Release notes")?
		weekly_text = Domains.document("Revenue grew this week.\nFollow up with the customer team.")?
		release_text = Domains.document("A small release.\nTwo changes.\nReady for review.")?
		Ok([
			Example.Step.command(
				Commands.submit,
				{
					title: weekly,
					text: weekly_text,
				},
			),
			Example.Step.command(
				Commands.submit,
				{
					title: release,
					text: release_text,
				},
			),
			Example.Step.command(Commands.sweep, {}),
		])
	}
}
