import pf.Example
import pf.TextMap
import pf.TextSet
import Commands

Demo :: [].{
	definition = Example.define("demo", steps({}))

	steps = |_| {
		attributes = TextMap.from_entries([{ key: "role", value: "reader" }]).map_err(|_| "invalid map")?
		groups = TextSet.from_list(["eng"]).map_err(|_| "invalid set")?
		Ok([
			Example.Step.command(
				Commands.tag,
				{ name: "seeded", tags: ["docs", "runbook"], attributes, groups },
			),
		])
	}
}
