import pf.Example
import Commands

Demo :: [].{
	definition : Example
	definition = Example.define("seed_chart", steps({}))

	steps : {} -> Try(List(Example.Step), Str)
	steps = |_| Ok([
		Example.Step.command(
			Commands.append_sample,
			{ time: 1_735_689_600_000, value: 0, missing: Bool.False },
		),
		Example.Step.command(
			Commands.append_sample,
			{ time: 1_735_862_400_000, value: 72, missing: Bool.False },
		),
		Example.Step.command(
			Commands.append_sample,
			{ time: 1_736_035_200_000, value: 0, missing: Bool.True },
		),
		Example.Step.command(
			Commands.append_sample,
			{ time: 1_736_208_000_000, value: 91, missing: Bool.False },
		),
	])
}
