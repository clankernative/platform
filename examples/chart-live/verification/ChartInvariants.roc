import pf.Api
import Data

ChartInvariants :: [].{
	samples = Api.invariant(
		Data.chart_samples,
		"Samples have nonblank owners, legal values and timestamps, unique owner/time pairs, and at most 100 rows per owner.",
		Data.snapshot,
		|state| state.chart_samples.all(
			|row|
				!row.value.owner.is_empty()
					and row.value.owner == row.value.owner.trim()
					and row.value.time >= 0
					and row.value.time <= 4_102_444_800_000
					and row.value.value >= 0
					and row.value.value <= 100
					and state.chart_samples.keep_if(
						|other|
							other.value.owner == row.value.owner and other.value.time == row.value.time,
					).len() == 1
					and state.chart_samples.keep_if(|other| other.value.owner == row.value.owner).len() <= 100,
		),
	)
}
