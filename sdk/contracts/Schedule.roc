import Write
import ScheduleBinding

# A platform-owned trigger for an existing internal command. A schedule adds no
# handler, no phase and no result shape: it names a command that already exists
# and the fixed input it is called with. There is no actor and no request to
# derive an input from, so the input is fixed where the schedule is declared.
Schedule(a) :: { binding : ScheduleBinding }.{
	# After an outage a schedule has a backlog. Running seventy-two hourly digests
	# to catch up is rarely what an author wants, and dropping them silently is
	# rarely safe, so every constructor takes this explicitly. There is no default
	# because there is no answer that is right for both a digest and a sweep.
	Missed : [
		# Run once for the most recent occurrence; record the superseded ones.
		Coalesce,
		# Run each missed occurrence in order, up to this bound, then fail closed
		# rather than growing without limit.
		RunEach(U64),
	]

	minute_ms : U64
	minute_ms = 60_000

	# Recurrences are written in the unit the author means. Seconds alone would
	# force every_seconds(86_400) for a daily job, which reads badly and invites an
	# off-by-24 error.
	every_minutes : U64, Write(a, b), a, Missed -> Schedule(a)
	every_minutes = |minutes, command, input, missed| build(minutes * minute_ms, -1, command, input, missed)

	every_hours : U64, Write(a, b), a, Missed -> Schedule(a)
	every_hours = |hours, command, input, missed| build(hours * 60 * minute_ms, -1, command, input, missed)

	# Daily schedules take their anchor as an argument rather than a later builder
	# step, so a schedule with no anchor cannot be written down. "Every day"
	# measured from the last run drifts after every outage, which makes the
	# occurrence identity unstable and defeats the exactly-once derivation. The
	# hour is UTC.
	daily_at_hour : I64, Write(a, b), a, Missed -> Schedule(a)
	daily_at_hour = |hour, command, input, missed| build(24 * 60 * minute_ms, hour, command, input, missed)

	build : U64, I64, Write(a, b), a, Missed -> Schedule(a)
	build = |interval_ms, anchor_hour, command, input, missed| {
		operation = command.metadata()
		policy = match missed {
			Coalesce => { missed: "coalesce", catch_up_bound: 0.U64 }
			RunEach(bound) => { missed: "run_each", catch_up_bound: bound }
		}
		{
			binding: ScheduleBinding.define({
				# The App.definition.schedules record supplies the registered name,
				# exactly as it supplies a page's.
				name: "",
				operation: operation.name,
				input: command.encode_input(input),
				input_type: operation.input_type,
				interval_ms,
				anchor_hour,
				missed: policy.missed,
				catch_up_bound: policy.catch_up_bound,
			}),
		}
	}

	register : Schedule(a) -> ScheduleBinding
	register = |schedule| schedule.binding
}
