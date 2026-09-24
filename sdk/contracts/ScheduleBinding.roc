# Registered schedule metadata. The host derives occurrences and supplies the
# actor; this binding carries no clock, no actor and no authority. Possessing one
# grants nothing — admission checks that the bound command exists and is internal,
# and the instance binds the actor a schedule runs as.
ScheduleBinding :: { metadata : Metadata }.{
	Metadata : {
		name : Str,
		operation : Str,
		input : Str,
		input_type : Str,
		interval_ms : U64,
		# Hour of the UTC day a daily schedule is anchored to, or -1 when the
		# recurrence is short enough to need no anchor. A local-time anchor is
		# ambiguous twice a year, so the platform does not offer one.
		anchor_hour : I64,
		# "coalesce" or "run_each". Never defaulted: see Schedule.
		missed : Str,
		catch_up_bound : U64,
	}

	define : Metadata -> ScheduleBinding
	define = |metadata| { metadata: metadata }

	metadata : ScheduleBinding -> Metadata
	metadata = |binding| binding.metadata

	named : Str, ScheduleBinding -> ScheduleBinding
	named = |name, binding| { ..binding, metadata: { ..binding.metadata, name } }
}
