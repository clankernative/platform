import pf.Example
import Commands

Demo :: [].{
	definition : Example
	definition = Example.define("seed_chart", steps({}))

	steps : {} -> Try(List(Example.Step), Str)
	steps = |_| Ok([
		Example.Step.command(
			Commands.append_sample,
			{ time: 1735689600000, value: 0, missing: Bool.False },
		),
		Example.Step.command(
			Commands.append_sample,
			{ time: 1735862400000, value: 72, missing: Bool.False },
		),
		Example.Step.command(
			Commands.append_sample,
			{ time: 1736035200000, value: 0, missing: Bool.True },
		),
		Example.Step.command(
			Commands.append_sample,
			{ time: 1736208000000, value: 91, missing: Bool.False },
		),
	])
}
