import pf.Schedule
import Commands
import SweepReportsTypes

Schedules :: [].{
	# Five minutes is a reconciliation cadence, not a delivery one: notify already
	# runs on the write path, so this only has to catch what that path lost.
	#
	# Coalesce, not run_each: after an outage the sweep's work is defined by
	# current state, so running the twelve occurrences an hour of downtime produced
	# would do the same thing twelve times. run_each belongs to schedules whose
	# occurrences each mean something -- an hourly digest covering its own hour.
	sweep : Schedule(SweepReportsTypes.Input)
	sweep = Schedule.every_minutes(5, Commands.sweep, {}, Coalesce)
}
