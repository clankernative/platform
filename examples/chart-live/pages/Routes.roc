import pf.Page
import ChartQueryTypes
import Reads
import Templates

# Defaults select the bounded UTC week 2025-01-01 through 2025-01-08 (end exclusive).
Routes :: [].{
	home : Page(ChartQueryTypes.Input)
	home = Page.route(
		{ title: "Chart live", path: "/", template: Templates.home },
		Reads.chart,
	)
		.with_defaults({ start: 1735689600000, end: 1736294400000 })

	chart : Page(ChartQueryTypes.Input)
	chart = Page.route(
		{ title: "Live sample chart", path: "/chart", template: Templates.chart },
		Reads.chart,
	)
		.with_defaults({ start: 1735689600000, end: 1736294400000 })
		.live()
}
