import pf.Api
import Data

# Completed statistics match the current row, including after internal commands.
ReportInvariants :: [].{
	reports = Api.invariant(
		Data.reports,
		"Completed statistics match the current document; pending analysis has zero statistics; an announced report is ready.",
		Data.snapshot,
		|state|
			state.reports.all(
				|row| {
					# An announcement describes a ready revision, so it cannot
					# outlive one: revising withdraws both together.
					consistent = !row.value.announced or row.value.ready
					if row.value.ready {
						text = row.value.text.to_str()
						consistent
							and row.value.bytes == text.count_utf8_bytes()
								and row.value.lines == text.split_on("\n").len()
					} else {
						consistent and row.value.bytes == 0 and row.value.lines == 0
					}
				},
			),
	)
}
