import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import Errors
import pf.Selection
import pf.Predicate
import AppendSampleTypes
import Models
import Data

AppendSample :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.chart_samples)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, AppendSampleTypes.Input -> Tx(AppendSampleTypes.Output)
	handle = |context, input|
		if input.time < 0 or input.time > 4_102_444_800_000 or input.value < 0 or input.value > 100 {
			Tx.reject(Errors.invalid_sample)
		} else {
			owner = context.actor()
			owned = Selection.filter(
				Data.chart_samples,
				Predicate.all([Data.chart_samples_owner_equal(owner)]),
			)
			Tx.collect(owned, 100.U64).and_then(
				|rows|
					if rows.len() >= 100 or rows.any(|row| row.value.time == input.time) {
						Tx.reject(Errors.invalid_sample)
					} else {
						Tx.create(
							Data.chart_samples,
						{ owner, time: input.time, value: input.value, missing: input.missing },
						)
							.map(|_| { time: input.time, owner })
					},
			)
		}

	contract = {
		errors: [Errors.invalid_sample],
		title: "Append a chart sample",
		usage: {
			purpose: "Append one sample to the current actor's persisted time series.",
			use_when: ["Recording a new observation at an unused UTC-millisecond timestamp."],
			avoid_when: ["Changing a previously recorded timestamp; sample timestamps are immutable."],
			preconditions: [
				"Timestamp is in UTC milliseconds from epoch through 2100-01-01, and unique for this actor.",
				"Value is an integer from 0 through 100; missing samples may carry any in-range value.",
			],
			effects: ["Creates a sample owned by the current actor; timestamps are unique per actor."],
			result: "The timestamp committed by the command.",
		},
		inputs: {
			time: "UTC milliseconds since the Unix epoch, from 0 through 2100-01-01; unique among this actor's samples.",
			value: "Integer observation from 0 through 100. Zero is an ordinary measured value.",
			missing: "True marks an explicit gap; it does not reinterpret a numeric zero as missing.",
		},
		outputs: {
			time: "The persisted sample timestamp in UTC milliseconds.",
			owner: "The current actor who owns the created sample.",
		},
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : AppendSampleTypes.Input, output : AppendSampleTypes.Output }, Str)
	example = |_| Ok({
		input: { time: 1735689600000, value: 0, missing: Bool.False },
		output: { time: 1735689600000, owner: "example-actor" },
	})

	verify_input : Str, U64 -> Try(AppendSampleTypes.Input, Str)
	verify_input = |_snapshot, seed| {
		delta = (seed % 1_000_000).to_i64_try().map_err(|_| "invalid bounded seed")?
		Ok({ time: 1735689600000 + delta, value: 0, missing: Bool.False })
	}

	verify_result : Str, AppendSampleTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		row = next.chart_samples.find_first(|candidate| candidate.value.time == saved.time)
			.map_err(|_| "created sample missing")?
		Ok(
			old.chart_samples.len() + 1 == next.chart_samples.len()
				and row.value.owner == saved.owner
				and row.value.owner != ""
				and row.value.time == saved.time
				and row.value.value == 0
				and !row.value.missing,
		)
	}
}
