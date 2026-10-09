import AppendSample
import UpdateSample
import ChartQuery
import Routes
import ChartInvariants
import Demo
import ChartErrors

App :: [].{
	definition = {
		namespace: "chart_live",
		operations: {
			append_sample: AppendSample.definition,
			update_sample: UpdateSample.definition,
			chart: ChartQuery.definition,
		},
		pages: { home: Routes.home.register(), chart: Routes.chart.register() },
		properties: { chart_samples: ChartInvariants.samples }
		errors: {
			invalid_sample: ChartErrors.invalid_sample,
			sample_edit_rejected: ChartErrors.sample_edit_rejected,
			invalid_range: ChartErrors.invalid_range,
		},
		examples: [Demo.definition],
		presentation: { stylesheet: "app.css", script: "app.js" },
	}
}
