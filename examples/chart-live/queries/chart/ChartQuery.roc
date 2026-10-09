import pf.Api
import pf.Handler
import pf.Context
import pf.CollectionPage
import pf.Query
import Errors
import pf.Selection
import pf.Predicate
import ChartQueryTypes
import ChartView
import Models
import Data

ChartQuery :: [].{
	definition = Api.query({
		handler: Handler.local(handle),
		contract,
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, ChartQueryTypes.Input -> Query(ChartView.Result)
	handle = |context, input|
		if !valid_range(input.start, input.end) {
			Query.from_try(Err(Errors.invalid_range))
		} else {
			owned = Selection.filter(
				Data.chart_samples,
				Predicate.all([Data.chart_samples_owner_equal(context.actor())]),
			)
				.order([Data.chart_samples_time_asc])
			Query.collect(owned, 100.U64).map(
				|rows| {
					selected = rows.keep_if(
						|row| row.value.time >= input.start and row.value.time < input.end,
					)
					{
					title: "Chart samples",
					full_start: 1735689600000,
					full_end: 1736294400000,
					sample_edits: CollectionPage.complete(selected.map(
						|row|
							{
								sample_time: row.value.time,
								expected_version: row.version,
								value: row.value.value,
								missing: row.value.missing,
							},
					)),
					chart: {
						width: 640,
						height: 240,
						start: input.start,
						end: input.end,
						title: "Chart samples",
						kind: "line",
						samples: CollectionPage.complete(selected.map(
							|row|
							{
								time: row.value.time,
								value: row.value.value,
								missing: row.value.missing,
								key: row.id.to_str(),
							},
						)),
						y_min: 0,
						y_max: 100,
					},
					}
				},
			)
		}

	valid_range : I64, I64 -> Bool
	valid_range = |start, end|
		start >= 0 and end > start and end <= 4_102_444_800_001 and end - start <= 2_678_400_000

	contract = {
		errors: [Errors.invalid_range],
		title: "Read chart samples",
		usage: {
			purpose: "Read the current actor's persisted samples in a checked UTC time interval.",
			use_when: ["Rendering the chart or choosing another bounded interval."],
			avoid_when: ["Writing or correcting a sample."],
			preconditions: [
				"Start is nonnegative; end is exclusive and later than start; range is at most 31 days.",
				"End is no later than 2100-01-01 UTC.",
			],
			effects: [],
			result: "Page title and fixed renderer input containing only current owned rows in the selected interval.",
		},
		inputs: {
			start: "Inclusive UTC milliseconds since the Unix epoch.",
			end: "Exclusive UTC milliseconds since the Unix epoch; at most 31 days after start.",
		},
		outputs: ChartView.fields,
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : ChartQueryTypes.Input, output : ChartView.Result }, Str)
	example = |_| Ok({
		input: { start: 1735689600000, end: 1736294400000 },
		output: {
			title: "Chart samples",
			full_start: 1735689600000,
			full_end: 1736294400000,
			sample_edits: CollectionPage.empty,
			chart: {
				width: 640,
				height: 240,
				start: 1735689600000,
				end: 1736294400000,
				title: "Chart samples",
				kind: "line",
				samples: CollectionPage.empty,
				y_min: 0,
				y_max: 100,
			},
		},
	})

	verify_input : Str, U64 -> Try(ChartQueryTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok({ start: 1735689600000, end: 1736294400000 })

	verify_result : Str, ChartView.Result, Str -> Try(Bool, Str)
	verify_result = |before, result, after| {
		state = Data.snapshot(before)?
		chart = result.chart
		times = CollectionPage.items(chart.samples).map(|sample| sample.time)
		ordered_times = times.sort_with(|left, right| if left < right { Before } else if left > right { After } else { Same })
		Ok(
			before == after
				and chart.width == 640
				and chart.height == 240
				and chart.y_min == 0
				and chart.y_max == 100
				and chart.kind == "line"
				and result.full_start == 1735689600000
				and result.full_end == 1736294400000
				and chart.start >= 0
				and chart.end > chart.start
				and chart.end <= 4_102_444_800_001
				and chart.end - chart.start <= 2_678_400_000
				and times == ordered_times
				and CollectionPage.items(chart.samples).all(
					|sample|
						sample.time >= chart.start
							and sample.time < chart.end
							and sample.value >= 0
							and sample.value <= 100
							and sample.time <= 4_102_444_800_000
							and state.chart_samples.any(
								|row|
									row.id.to_str() == sample.key
										and row.value.time == sample.time
										and row.value.value == sample.value
										and row.value.missing == sample.missing,
							),
				),
		)
	}
}
