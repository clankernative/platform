import pf.Example
import Commands

Demo :: [].{
	definition : Example
	definition = Example.define("demo", steps({}))

	steps : {} -> Try(List(Example.Step), Str)
	steps = |_| Ok([Example.Step.command(Commands.open, { title: "Example on-call incident" })])
}
