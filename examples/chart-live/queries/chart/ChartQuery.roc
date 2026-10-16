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
						actor: context.actor(),
						title: "Chart samples",
						full_start: 1_735_689_600_000,
						full_end: 1_736_294_400_000,
						sample_edits: CollectionPage.complete(
							selected.map(
								|row|
									{
										sample_time: row.value.time,
										expected_version: row.version,
										value: row.value.value,
										missing: row.value.missing,
									},
							),
						),
						chart: {
							width: 640,
							height: 240,
							start: input.start,
							end: input.end,
							title: "Chart samples",
							kind: "line",
							samples: CollectionPage.complete(
								selected.map(
									|row|
										{
											time: row.value.time,
											value: row.value.value,
											missing: row.value.missing,
											key: row.id.to_str(),
										},
								),
							),
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
		input: { start: 1_735_689_600_000, end: 1_736_294_400_000 },
		output: {
			actor: "example-actor",
			title: "Chart samples",
			full_start: 1_735_689_600_000,
			full_end: 1_736_294_400_000,
			sample_edits: CollectionPage.empty({}),
			chart: {
				width: 640,
				height: 240,
				start: 1_735_689_600_000,
				end: 1_736_294_400_000,
				title: "Chart samples",
				kind: "line",
				samples: CollectionPage.empty({}),
				y_min: 0,
				y_max: 100,
			},
		},
	})

	verify_input : Str, U64 -> Try(ChartQueryTypes.Input, Str)
	verify_input = |_snapshot, seed| {
		days = (seed % 8).to_i64_try().map_err(|_| "invalid bounded seed")?
		start = 1_735_689_600_000 + days * 86_400_000
		duration = if seed % 3 == 0 {
			1
		} else if seed % 3 == 1 {
			86_400_000
		} else {
			2_678_400_000
		}
		Ok({ start, end: start + duration })
	}

	verify_result : Str, ChartView.Result, Str -> Try(Bool, Str)
	verify_result = |before, result, after| {
		context = Api.verification_context(before)?
		decoded : Try({ start : I64, end : I64 }, _)
		decoded = Json.parse(context.input)
		input = decoded.map_err(|_| "invalid_verification_input")?
		state = Data.verification_snapshot(before)?.live
		chart = result.chart
		expected_rows = state.chart_samples
			.keep_if(
				|row|
					row.value.owner == context.actor
						and row.value.time >= input.start
							and row.value.time < input.end,
			)
			.sort_with(
				|left, right|
					if left.value.time < right.value.time {
						Before
					} else if left.value.time > right.value.time {
						After
					} else {
						Same
					},
			)
		expected_samples = expected_rows.map(
			|row|
				{
					time: row.value.time,
					value: row.value.value,
					missing: row.value.missing,
					key: row.id.to_str(),
				},
		)
		expected_edits = expected_rows.map(
			|row| {
				sample_time: row.value.time,
				expected_version: row.version,
				value: row.value.value,
				missing: row.value.missing,
			},
		)
		actual_samples = CollectionPage.items(chart.samples)
		Ok(
			[
				before == after,
				result.actor == context.actor,
				result.title == "Chart samples",
				chart.title == "Chart samples",
				result.sample_edits.items() == expected_edits,
				!result.sample_edits.has_more(),
				result.sample_edits.next_after().is_start(),
				!chart.samples.has_more(),
				chart.samples.next_after().is_start(),
				chart.width == 640,
				chart.height == 240,
				chart.y_min == 0,
				chart.y_max == 100,
				chart.kind == "line",
				result.full_start == 1_735_689_600_000,
				result.full_end == 1_736_294_400_000,
				chart.start == input.start,
				chart.end == input.end,
				expected_samples == actual_samples,
			].all(|passed| passed),
		)
	}
}
