import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import Errors
import pf.Selection
import pf.Predicate
import pf.RowVersion
import UpdateSampleTypes
import Models
import Data
import Selectors

UpdateSample :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([
			Api.update(
				Data.chart_samples,
				[
					Api.field(Selectors.chart_samples_value),
					Api.field(Selectors.chart_samples_missing),
				],
			),
		]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, UpdateSampleTypes.Input -> Tx(UpdateSampleTypes.Output)
	handle = |context, input|
		if input.value < 0 or input.value > 100 {
			Tx.reject(Errors.sample_edit_rejected)
		} else {
			owned_sample = Selection.filter(
				Data.chart_samples,
				Predicate.all([
					Data.chart_samples_owner_equal(context.actor()),
					Data.chart_samples_time_equal(input.sample_time),
				]),
			)
			Tx.find(owned_sample).and_then(
				|found|
					match found {
						None => Tx.reject(Errors.sample_edit_rejected)
						Some(row) =>
							if row.version != input.expected_version {
								Tx.reject(Errors.sample_edit_rejected)
							} else {
								Tx.update(
									Data.chart_samples,
									row,
									{ ..row.value, value: input.value, missing: input.missing },
								)
									.map(|updated| { time: updated.value.time, version: updated.version })
							}
						},
			)
		}

	contract = {
		errors: [Errors.sample_edit_rejected],
		title: "Update a chart sample",
		usage: {
			purpose: "Change the value or explicit gap state of a sample owned by the current actor.",
			use_when: ["Correcting an existing observation while holding its current row version."],
			avoid_when: ["Appending a sample or changing its timestamp."],
			preconditions: ["The caller owns the sample; the expected version is current; value is 0 through 100."],
			effects: ["Updates the persisted row atomically without changing its timestamp or owner."],
			result: "The unchanged timestamp and newly committed row version.",
		},
		inputs: {
			sample_time: "The sample's UTC timestamp, unique within the current actor's series.",
			expected_version: "Current revision of the sample, required to reject stale edits.",
			value: "Integer observation from 0 through 100.",
			missing: "True marks an explicit gap independently of the numeric value.",
		},
		outputs: { time: "The unchanged UTC timestamp.", version: "The new committed sample revision." },
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
	}

	example : {} -> Try({ input : UpdateSampleTypes.Input, output : UpdateSampleTypes.Output }, Str)
	example = |_| {
		version = RowVersion.from_u64(2.U64).map_err(|_| "invalid example version")?
		Ok({
			input: { sample_time: 1_735_689_600_000, expected_version: RowVersion.one, value: 0, missing: Bool.False },
			output: { time: 1_735_689_600_000, version },
		})
	}

	verify_input : Str, U64 -> Try(UpdateSampleTypes.Input, Str)
	verify_input = |snapshot, _seed| {
		context = Api.verification_context(snapshot)?
		state = Data.verification_snapshot(snapshot)?.live
		row = state.chart_samples.find_first(|candidate| candidate.value.owner == context.actor)
			.map_err(|_| "sample update verification requires owned seeded data")?
		Ok({
			sample_time: row.value.time,
			expected_version: row.version,
			value: if row.value.value == 100 {
				99
			} else {
				row.value.value + 1
			},
			missing: !row.value.missing,
		})
	}

	verify_result : Str, UpdateSampleTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		context = Api.verification_context(before)?
		decoded : Try({ sample_time : I64, expected_version : U64, value : I64, missing : Bool }, _)
		decoded = Json.parse(context.input)
		input = decoded.map_err(|_| "invalid_verification_input")?
		old = Data.verification_snapshot(before)?
		next = Data.verification_snapshot(after)?
		original = old.live.chart_samples.find_first(
			|row| row.value.owner == context.actor and row.value.time == input.sample_time,
		)
			.map_err(|_| "sample missing before update")?
		version = RowVersion.from_u64(original.version.to_u64() + 1).map_err(|_| "invalid next revision")?
		expected = old.live.chart_samples.map(
			|row| if row.id == original.id {
				{ ..row, version, value: { ..row.value, value: input.value, missing: input.missing } }
			} else {
				row
			},
		)
		Ok(
			[
				original.version.to_u64() == input.expected_version,
				saved.time == input.sample_time,
				saved.version == version,
				next == { ..old, live: { ..old.live, chart_samples: expected } },
			].all(|passed| passed),
		)
	}
}
