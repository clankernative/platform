import pf.Example
import Commands
import Domains

Demo :: [].{
	definition : Example
	definition = Example.define("initialized", steps({}))

	steps : {} -> Try(List(Example.Step), Str)
	steps = |_| {
		title = Domains.title("Conformance deal")?
		Ok([
			Example.Step.command(
				Commands.seed,
				{ title: title },
			),
		])
	}
}
