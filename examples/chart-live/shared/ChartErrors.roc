import pf.Api
import pf.RowVersion
import Commands
import Reads
import Data

ChartErrors :: [].{
	invalid_sample = Api.error({
		description: "The sample fields are invalid, its timestamp is duplicated, or the actor's sample limit is reached.",
		recovery: "Use a timestamp from epoch through 2100-01-01, an in-range value, and no more than 100 samples."
		verification: |_| Api.failed_command(
			Commands.append_sample,
			|_snapshot, _seed| Ok({ time: 1735689600000, value: 101, missing: Bool.False }),
		),
	})

	sample_edit_rejected = Api.error({
		description: "The sample is not editable by this actor or its expected revision is stale.",
		recovery: "Select an owned sample and submit its current version.",
		verification: |_| Api.failed_command(
			Commands.update_sample,
			|snapshot, _seed| {
				state = Data.snapshot(snapshot)?
				row = state.chart_samples.first().map_err(|_| "seed a sample before verifying sample edits")?
				expected = RowVersion.from_u64(row.version.to_u64() + 1).map_err(|_| "invalid expected version")?
				Ok({
					sample_time: row.value.time,
					expected_version: expected,
					value: row.value.value,
					missing: row.value.missing,
				})
			},
		),
	})

	invalid_range = Api.error({
		description: "The requested UTC time range is invalid or exceeds 31 days.",
		recovery: "Choose a nonnegative start and a later exclusive end within 31 days.",
		verification: |_| Api.failed_query(
			Reads.chart,
			|_snapshot, _seed| Ok({ start: 1735689600000, end: 1735689600000 }),
		),
	})
}
