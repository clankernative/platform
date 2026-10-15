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
		.with_defaults({ start: 1_735_689_600_000, end: 1_736_294_400_000 })

	chart : Page(ChartQueryTypes.Input)
	chart = Page.route(
		{ title: "Live sample chart", path: "/chart", template: Templates.chart },
		Reads.chart,
	)
		.with_defaults({ start: 1_735_689_600_000, end: 1_736_294_400_000 })
		.live()
}
